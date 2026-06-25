"""Tests for the refactored Admin Console: sidebar shell, sub-pages,
inbox merged feed, audit pagination, and the /dashboard/ -> /admin/ swap.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from django.urls import reverse
from django.utils import timezone as dj_tz

from advisories.models import Advisory, AdvisoryIntakeMetadata, Kind, State
from audit.models import Action, AuditLogEntry
from audit.retention import _audit_trigger_bypass
from publication.models import PublicationTask, PublicationTaskStatus
from workflows import services as wf

SECTIONS = ["index", "cves", "publications", "audit", "project_list", "stats"]


def _backdate(entry, when):
    """Set an audit entry's created_at for the date-filter tests.

    The append-only Postgres trigger forbids UPDATE on audit_auditlogentry, so
    lower session_replication_role for this one write. Same escape hatch
    production code uses (audit.retention).
    """
    with _audit_trigger_bypass():
        AuditLogEntry.objects.filter(pk=entry.pk).update(created_at=when)


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x", created_by=member)
    return {"admin": admin, "member": member, "project": project, "advisory": advisory}


# ----- Per-sub-page admin gating -----------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("section", SECTIONS)
def test_subpage_403_for_non_admin(client, setup, section):
    client.force_login(setup["member"])
    response = client.get(reverse(f"admin_console:{section}"))
    assert response.status_code == 403


@pytest.mark.django_db
@pytest.mark.parametrize("section", SECTIONS)
def test_subpage_200_for_admin(client, setup, section):
    client.force_login(setup["admin"])
    response = client.get(reverse(f"admin_console:{section}"))
    assert response.status_code == 200


# ----- Sidebar nav rendering --------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("section", SECTIONS)
def test_sidebar_links_render_on_each_page(client, setup, section):
    client.force_login(setup["admin"])
    body = client.get(reverse(f"admin_console:{section}")).content.decode()
    # Every sidebar href must be present.
    for url_name in ["index", "project_list", "cves", "publications", "audit", "stats"]:
        assert reverse(f"admin_console:{url_name}") in body, (
            f"sidebar link {url_name} missing on {section}"
        )


@pytest.mark.django_db
def test_sidebar_marks_current_section(client, setup):
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:cves")).content.decode()
    # The CVE link should have aria-current="page"; other links should not.
    cves_url = reverse("admin_console:cves")
    inbox_url = reverse("admin_console:index")
    # Crude but specific: find each link and check for aria-current on the right one.
    cves_link_idx = body.find(f'href="{cves_url}"')
    inbox_link_idx = body.find(f'href="{inbox_url}"')
    assert cves_link_idx != -1 and inbox_link_idx != -1
    # Look at a 200-char window around each href for aria-current.
    cves_window = body[cves_link_idx : cves_link_idx + 200]
    inbox_window = body[inbox_link_idx : inbox_link_idx + 200]
    assert 'aria-current="page"' in cves_window
    assert 'aria-current="page"' not in inbox_window


# ----- Inbox merged feed -----------------------------------------------


@pytest.mark.django_db
def test_inbox_lists_cve_request_in_merged_feed(client, setup):
    wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:index")).content.decode()
    # Badge + advisory id present means the CVE request is in the feed.
    assert "inbox-badge--cve" in body
    assert setup["advisory"].advisory_id in body


@pytest.mark.django_db
def test_inbox_cve_row_links_to_cve_queue_not_advisory(client, setup):
    """The CVE-assignment row deep-links to the CVE queue (where assigning a
    CVE actually happens), not the advisory detail page where admins can't."""
    from workflows.models import CveRequestStatus, CveRequestTask

    wf.request_cve(setup["advisory"], by=setup["member"])
    task = CveRequestTask.objects.get(advisory=setup["advisory"], status=CveRequestStatus.QUEUED)
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index"))
    item = next(i for i in response.context["page"].object_list if i.kind == "cve")
    assert item.url == reverse("admin_console:cves") + f"#cve-task-{task.pk}"


@pytest.mark.django_db
def test_inbox_failed_publication_row_links_to_publication_queue(client, setup):
    """The failed-publication row deep-links to the publication queue (where
    Retry lives), not the advisory detail page."""
    task = PublicationTask.objects.create(
        advisory=setup["advisory"],
        version=setup["advisory"].versions.get(version=1),
        enqueued_by=setup["admin"],
        status=PublicationTaskStatus.FAILED,
        last_error="boom",
    )
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index"))
    item = next(i for i in response.context["page"].object_list if i.kind == "pub_failed")
    assert item.url == reverse("admin_console:publications") + f"#pub-task-{task.pk}"


@pytest.mark.django_db
def test_inbox_republish_required_row_links_to_advisory_detail(client, setup):
    """A published advisory edited since its last publish surfaces in the
    "publish required" category and links to the advisory detail page (where
    the Re-publish button lives), not to the publication queue."""
    adv = Advisory.objects.create(
        project=setup["project"],
        summary="edited",
        state=State.PUBLISHED,
        republish_required=True,
    )
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index"))
    item = next(i for i in response.context["page"].object_list if i.kind == "republish")
    assert item.title == adv.advisory_id
    assert item.url == reverse("advisories:detail", args=[adv.advisory_id])


@pytest.mark.django_db
def test_inbox_publish_required_category_filters_both(client, setup):
    """?category=needs_publish surfaces both failed exports and
    republish-required advisories, and the count sums both sources."""
    PublicationTask.objects.create(
        advisory=setup["advisory"],
        version=setup["advisory"].versions.get(version=1),
        enqueued_by=setup["admin"],
        status=PublicationTaskStatus.FAILED,
        last_error="boom",
    )
    republish = Advisory.objects.create(
        project=setup["project"],
        summary="edited",
        state=State.PUBLISHED,
        republish_required=True,
    )
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index") + "?category=needs_publish")
    kinds = {i.kind for i in response.context["page"].object_list}
    titles = {i.title for i in response.context["page"].object_list}
    assert kinds == {"pub_failed", "republish"}
    assert {setup["advisory"].advisory_id, republish.advisory_id} <= titles
    assert response.context["counts"]["needs_publish"] == 2


@pytest.mark.django_db
def test_inbox_failed_republish_appears_once(client, setup):
    """A failed *re*-publish leaves both a FAILED task and republish_required
    set on the advisory. It must surface exactly once — as the failed-task row,
    which carries the actionable error + Retry."""
    adv = Advisory.objects.create(
        project=setup["project"],
        summary="edited",
        state=State.PUBLISHED,
        republish_required=True,
    )
    PublicationTask.objects.create(
        advisory=adv,
        version=adv.versions.get(version=1),
        enqueued_by=setup["admin"],
        status=PublicationTaskStatus.FAILED,
        last_error="boom",
    )
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index"))
    matching = [i for i in response.context["page"].object_list if i.title == adv.advisory_id]
    assert len(matching) == 1
    assert matching[0].kind == "pub_failed"
    assert response.context["counts"]["needs_publish"] == 1


@pytest.mark.django_db
def test_inbox_republish_excludes_ghsa_linked(client, setup):
    """GHSA-linked advisories auto-re-publish (INV-GHSA-3) — they carry no human
    action and are kept out of the "publish required" category and count."""
    Advisory.objects.create(
        project=setup["project"],
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        ghsa_owner="eclipse",
        ghsa_repo="widget",
        state=State.PUBLISHED,
        republish_required=True,
    )
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index"))
    assert not [i for i in response.context["page"].object_list if i.kind == "republish"]
    assert response.context["counts"]["needs_publish"] == 0


@pytest.mark.django_db
def test_inbox_orders_items_by_age_desc(client, setup):
    # Older CVE request, newer review submission. CVE is created first
    # because submit_for_review locks editing; the resulting review row
    # will therefore have a newer created_at than the CVE task.
    wf.request_cve(setup["advisory"], by=setup["member"])
    wf.submit_for_review(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:index")).content.decode()
    cve_idx = body.find("inbox-badge--cve")
    rev_idx = body.find("inbox-badge--review")
    assert cve_idx != -1 and rev_idx != -1
    assert rev_idx < cve_idx, "newer review submission should appear above older CVE request"


@pytest.mark.django_db
def test_inbox_empty_state_for_admin(client, setup):
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:index")).content.decode()
    assert "you&#x27;re all caught up" in body.lower() or "all caught up" in body.lower()


@pytest.mark.django_db
def test_inbox_marks_flagged_triage_advisory(client, setup):
    """Flagged triage rows render with the Routing badge; non-flagged with Triage."""
    flagged = Advisory.objects.create(
        project=setup["project"],
        summary="needs re-routing",
        created_by=setup["member"],
        state=State.TRIAGE,
    )
    AdvisoryIntakeMetadata.objects.create(
        advisory=flagged,
        needs_admin_routing=True,
        admin_routing_note="belongs to bravo, not us",
    )
    normal = Advisory.objects.create(
        project=setup["project"],
        summary="regular triage",
        created_by=setup["member"],
        state=State.TRIAGE,
    )
    AdvisoryIntakeMetadata.objects.create(advisory=normal, needs_admin_routing=False)
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index"))
    items = {i.title: i for i in response.context["page"].object_list}
    assert items["needs re-routing"].badge == "Routing"
    assert items["needs re-routing"].badge_class == "inbox-badge--triage-routing"
    assert items["regular triage"].badge == "Triage"
    assert items["regular triage"].badge_class == "inbox-badge--triage"


@pytest.mark.django_db
def test_inbox_excludes_ghsa_linked_triage(client, setup):
    """A GHSA-linked triage row is a read-only GitHub mirror (INV-GHSA-3) with no
    human action, so it stays out of the actionable inbox feed and triage count —
    while a native triage row on the same project still shows."""
    from advisories.models import Kind

    Advisory.objects.create(
        project=setup["project"],
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        ghsa_owner="eclipse",
        ghsa_repo="widget",
        summary="mirrored from github",
        state=State.TRIAGE,
    )
    Advisory.objects.create(
        project=setup["project"],
        summary="native triage report",
        created_by=setup["member"],
        state=State.TRIAGE,
    )
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index"))
    titles = {i.title for i in response.context["page"].object_list}
    assert "native triage report" in titles
    assert "mirrored from github" not in titles
    assert response.context["counts"]["triage"] == 1


@pytest.mark.django_db
def test_inbox_flagged_subtitle_includes_routing_note(client, setup):
    flagged = Advisory.objects.create(
        project=setup["project"],
        summary="needs re-routing",
        created_by=setup["member"],
        state=State.TRIAGE,
    )
    AdvisoryIntakeMetadata.objects.create(
        advisory=flagged,
        needs_admin_routing=True,
        admin_routing_note="belongs to bravo, not us",
    )
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index"))
    item = next(i for i in response.context["page"].object_list if i.title == "needs re-routing")
    assert setup["project"].slug in item.subtitle
    assert "belongs to bravo, not us" in item.subtitle


@pytest.mark.django_db
def test_inbox_counts_include_routing_subset(client, setup):
    Advisory.objects.create(
        project=setup["project"], summary="t1", created_by=setup["member"], state=State.TRIAGE
    )
    flagged = Advisory.objects.create(
        project=setup["project"], summary="t2", created_by=setup["member"], state=State.TRIAGE
    )
    AdvisoryIntakeMetadata.objects.create(
        advisory=flagged, needs_admin_routing=True, admin_routing_note="x"
    )
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index"))
    assert response.context["counts"]["triage"] == 2
    assert response.context["counts"]["triage_routing"] == 1
    assert "awaiting routing" in response.content.decode()


@pytest.mark.django_db
def test_inbox_routing_chip_hidden_when_zero(client, setup):
    Advisory.objects.create(
        project=setup["project"], summary="t1", created_by=setup["member"], state=State.TRIAGE
    )
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:index")).content.decode()
    assert "awaiting routing" not in body


@pytest.mark.django_db
def test_inbox_paginates_feed(client, setup):
    """The merged feed pages at INBOX_PER_PAGE rows."""
    from admin_console.views.inbox import INBOX_PER_PAGE

    total = INBOX_PER_PAGE + 5
    for i in range(total):
        adv = Advisory.objects.create(
            project=setup["project"], summary=f"a{i}", created_by=setup["member"]
        )
        wf.request_cve(adv, by=setup["member"])
    client.force_login(setup["admin"])
    page1 = client.get(reverse("admin_console:index"))
    assert page1.status_code == 200
    assert len(page1.context["page"].object_list) == INBOX_PER_PAGE
    assert page1.context["page"].paginator.num_pages == 2
    body1 = page1.content.decode()
    assert "page=2" in body1  # paginator "Next →" link

    page2 = client.get(reverse("admin_console:index") + "?page=2")
    assert page2.status_code == 200
    assert len(page2.context["page"].object_list) == total - INBOX_PER_PAGE


@pytest.mark.django_db
def test_inbox_pagination_preserves_category_filter(client, setup):
    """`?category=triage&page=2` keeps the filter and lands on page 2."""
    from admin_console.views.inbox import INBOX_PER_PAGE

    total = INBOX_PER_PAGE + 5
    for i in range(total):
        Advisory.objects.create(
            project=setup["project"],
            summary=f"t{i}",
            created_by=setup["member"],
            state=State.TRIAGE,
        )
    # And an unrelated CVE that should NOT show up under category=triage.
    wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index") + "?category=triage&page=2")
    assert response.status_code == 200
    page = response.context["page"]
    assert page.number == 2
    assert len(page.object_list) == total - INBOX_PER_PAGE
    assert all(i.kind == "triage" for i in page.object_list)
    body = response.content.decode()
    # The paginator's "Previous" link carries the category through.
    assert "category=triage" in body
    assert "page=1" in body


@pytest.mark.django_db
def test_inbox_filters_feed_to_category(client, setup):
    """?category=cve restricts the feed to CVE items but leaves global counts intact."""
    # One CVE request + one open review → two different kinds in the feed.
    wf.request_cve(setup["advisory"], by=setup["member"])
    other = Advisory.objects.create(
        project=setup["project"], summary="other", created_by=setup["member"]
    )
    wf.submit_for_review(other, by=setup["member"])
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index") + "?category=cve")
    assert response.status_code == 200
    kinds = {i.kind for i in response.context["page"].object_list}
    assert kinds == {"cve"}
    # Counts reflect global state, not the filter.
    assert response.context["counts"]["cve_open"] == 1
    assert response.context["counts"]["review_open"] == 1
    assert response.context["selected_category"] == "cve"
    body = response.content.decode()
    assert "inbox-counts__chip--active" in body


@pytest.mark.django_db
def test_inbox_filter_unknown_category_is_lenient(client, setup):
    """Bogus ?category= values fall back to the unfiltered feed."""
    wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index") + "?category=bogus")
    assert response.status_code == 200
    assert response.context["selected_category"] == ""
    # Feed not filtered: the CVE item is still there.
    assert any(i.kind == "cve" for i in response.context["page"].object_list)


# ----- /dashboard/ legacy path & disabled Django admin --------------------


@pytest.mark.django_db
def test_old_dashboard_path_404s(client, setup):
    # We did not add a redirect — old path should now 404.
    response = client.get("/dashboard/", follow=False)
    assert response.status_code == 404


@pytest.mark.django_db
def test_django_admin_disabled(client, setup):
    # Django's built-in admin was removed for defense-in-depth (it bypassed the
    # app's audited service layer); /admin/ is the only admin surface. Guard
    # against an accidental re-mount: /django-admin/ must 404 even for an admin.
    client.force_login(setup["admin"])
    assert client.get("/django-admin/").status_code == 404
    console = client.get("/admin/")
    assert console.status_code == 200
    assert "Admin Console" in console.content.decode() or "Inbox" in console.content.decode()


# ----- Audit log page ----------------------------------------------------


@pytest.mark.django_db
def test_audit_page_paginates(client, setup):
    for _ in range(60):
        AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    client.force_login(setup["admin"])
    page1 = client.get(reverse("admin_console:audit"))
    assert page1.status_code == 200
    body1 = page1.content.decode()
    # 50 per page
    assert body1.count("<tr>") - 1 == 50  # minus 1 for thead row
    page2 = client.get(reverse("admin_console:audit") + "?page=2")
    body2 = page2.content.decode()
    assert "Previous" in body2


@pytest.mark.django_db
def test_audit_page_shows_retention_note_after_prune(client, setup):
    AuditLogEntry.objects.create(
        action=Action.AUDIT_PRUNED,
        metadata={
            "operation": "prune_audit",
            "cutoff": datetime(2016, 6, 13, tzinfo=UTC).isoformat(),
            "deleted": 0,
        },
    )
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:audit")).content.decode()
    assert "under the retention policy" in body
    assert "2016-06-13" in body


@pytest.mark.django_db
def test_audit_page_no_retention_note_without_prune(client, setup):
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:audit")).content.decode()
    assert "under the retention policy" not in body


@pytest.mark.django_db
def test_audit_page_filters_by_action(client, setup):
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_PUBLISHED)
    client.force_login(setup["admin"])
    body = client.get(
        reverse("admin_console:audit") + f"?action={Action.ADVISORY_PUBLISHED}"
    ).content.decode()
    # The filter dropdown lists every Action so the strings appear there
    # regardless of the filter — look at the rendered table rows instead.
    table = body.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert Action.ADVISORY_PUBLISHED in table
    assert Action.ADVISORY_CREATED not in table


def _audit_table(body: str) -> str:
    return body.split("<tbody>", 1)[1].split("</tbody>", 1)[0]


@pytest.mark.django_db
def test_audit_page_filters_by_multiple_actions(client, setup):
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_PUBLISHED)
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_DISMISSED)
    client.force_login(setup["admin"])
    response = client.get(
        reverse("admin_console:audit")
        + f"?action={Action.ADVISORY_CREATED}&action={Action.ADVISORY_PUBLISHED}"
    )
    table = _audit_table(response.content.decode())
    assert Action.ADVISORY_CREATED in table
    assert Action.ADVISORY_PUBLISHED in table
    assert Action.ADVISORY_DISMISSED not in table


@pytest.mark.django_db
def test_audit_page_ignores_unknown_action_value(client, setup):
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:audit") + "?action=not-a-real-action")
    assert response.status_code == 200
    # Unknown action is silently dropped — all entries still listed.
    assert Action.ADVISORY_CREATED in _audit_table(response.content.decode())


@pytest.mark.django_db
def test_audit_page_filters_by_actor_email_substring(client, setup, make_user):
    other = make_user(email="alice.smith@example.org")
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    AuditLogEntry.objects.create(actor=other, action=Action.ADVISORY_EDITED)
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:audit") + "?actor=alice")
    table = _audit_table(response.content.decode())
    assert Action.ADVISORY_EDITED in table
    assert Action.ADVISORY_CREATED not in table


@pytest.mark.django_db
def test_audit_page_filters_by_actor_display_name(client, setup, make_user):
    other = make_user(email="x@example.org")
    other.display_name = "Bob Vance"
    other.save()
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    AuditLogEntry.objects.create(actor=other, action=Action.ADVISORY_EDITED)
    client.force_login(setup["admin"])
    table = _audit_table(
        client.get(reverse("admin_console:audit") + "?actor=Vance").content.decode()
    )
    assert Action.ADVISORY_EDITED in table
    assert Action.ADVISORY_CREATED not in table


@pytest.mark.django_db
def test_audit_page_filters_by_system_actor(client, setup):
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    AuditLogEntry.objects.create(actor=None, action=Action.GHSA_SYNC_RUN_STARTED)
    client.force_login(setup["admin"])
    table = _audit_table(
        client.get(reverse("admin_console:audit") + "?actor=system").content.decode()
    )
    assert Action.GHSA_SYNC_RUN_STARTED in table
    assert Action.ADVISORY_CREATED not in table


@pytest.mark.django_db
def test_audit_page_filters_advisory_id_case_insensitive_partial(client, setup):
    AuditLogEntry.objects.create(
        actor=setup["admin"], action=Action.ADVISORY_CREATED, advisory=setup["advisory"]
    )
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_EDITED)
    client.force_login(setup["admin"])
    target_id = setup["advisory"].advisory_id
    # Search a lowercased substring of the uppercase advisory_id to exercise
    # both case-insensitivity and substring matching.
    needle = target_id[:5].lower()
    table = _audit_table(
        client.get(reverse("admin_console:audit") + f"?advisory={needle}").content.decode()
    )
    assert target_id in table
    # The actor-only entry has no advisory and must not appear.
    assert Action.ADVISORY_EDITED not in table


@pytest.mark.django_db
def test_audit_page_filters_by_date_range_inclusive_until(client, setup):
    inside = AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    outside_before = AuditLogEntry.objects.create(
        actor=setup["admin"], action=Action.ADVISORY_EDITED
    )
    outside_after = AuditLogEntry.objects.create(
        actor=setup["admin"], action=Action.ADVISORY_DISMISSED
    )
    _backdate(inside, datetime(2026, 5, 23, 12, 0, tzinfo=UTC))
    _backdate(outside_before, datetime(2026, 4, 30, 23, 0, tzinfo=UTC))
    _backdate(outside_after, datetime(2026, 5, 24, 0, 30, tzinfo=UTC))
    client.force_login(setup["admin"])
    table = _audit_table(
        client.get(
            reverse("admin_console:audit") + "?since=2026-05-01&until=2026-05-23"
        ).content.decode()
    )
    # Inclusive boundary: 23:00 on 2026-05-23 must appear; 00:30 on 05-24 must not.
    assert Action.ADVISORY_CREATED in table
    assert Action.ADVISORY_EDITED not in table
    assert Action.ADVISORY_DISMISSED not in table


@pytest.mark.django_db
def test_audit_page_invalid_date_is_ignored(client, setup):
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:audit") + "?since=not-a-date")
    assert response.status_code == 200
    assert Action.ADVISORY_CREATED in _audit_table(response.content.decode())


@pytest.mark.django_db
def test_audit_page_preset_24h_filters_old_entries(client, setup):
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    old = AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_EDITED)
    # The recent entry keeps its auto-now timestamp; force `old` two days ago.
    _backdate(old, dj_tz.now() - timedelta(days=2))
    client.force_login(setup["admin"])
    table = _audit_table(
        client.get(reverse("admin_console:audit") + "?preset=24h").content.decode()
    )
    assert Action.ADVISORY_CREATED in table
    assert Action.ADVISORY_EDITED not in table


@pytest.mark.django_db
def test_audit_page_invalid_preset_is_ignored(client, setup):
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:audit") + "?preset=bogus")
    assert response.status_code == 200
    assert Action.ADVISORY_CREATED in _audit_table(response.content.decode())


@pytest.mark.django_db
def test_audit_page_explicit_since_overrides_preset(client, setup):
    week_old = AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    _backdate(week_old, dj_tz.now() - timedelta(days=5))
    client.force_login(setup["admin"])
    # preset=24h would hide a 5-day-old entry; explicit since=very-old must keep it.
    long_ago = (dj_tz.now() - timedelta(days=30)).date().isoformat()
    table = _audit_table(
        client.get(
            reverse("admin_console:audit") + f"?preset=24h&since={long_ago}"
        ).content.decode()
    )
    assert Action.ADVISORY_CREATED in table


@pytest.mark.django_db
def test_audit_page_metadata_freetext_match(client, setup):
    AuditLogEntry.objects.create(
        actor=setup["admin"],
        action=Action.ADVISORY_CREATED,
        metadata={"reason": "needle-XYZ"},
    )
    AuditLogEntry.objects.create(
        actor=setup["admin"],
        action=Action.ADVISORY_EDITED,
        metadata={"reason": "other"},
    )
    client.force_login(setup["admin"])
    table = _audit_table(
        client.get(reverse("admin_console:audit") + "?q=needle-XYZ").content.decode()
    )
    assert Action.ADVISORY_CREATED in table
    assert Action.ADVISORY_EDITED not in table


@pytest.mark.django_db
def test_audit_pagination_preserves_multi_action_filter(client, setup):
    for _ in range(55):
        AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    for _ in range(5):
        AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_PUBLISHED)
    client.force_login(setup["admin"])
    response = client.get(
        reverse("admin_console:audit")
        + f"?action={Action.ADVISORY_CREATED}&action={Action.ADVISORY_PUBLISHED}"
    )
    body = response.content.decode()
    # Both action params must survive on the Next link.
    assert "Next" in body
    assert f"action={Action.ADVISORY_CREATED}" in body
    assert f"action={Action.ADVISORY_PUBLISHED}" in body
    # Following the Next link should still return the second page with both filters.
    response2 = client.get(
        reverse("admin_console:audit")
        + f"?action={Action.ADVISORY_CREATED}&action={Action.ADVISORY_PUBLISHED}&page=2"
    )
    assert response2.status_code == 200
    body2 = response2.content.decode()
    assert "Previous" in body2


@pytest.mark.django_db
def test_audit_page_clear_link_when_filter_active(client, setup):
    AuditLogEntry.objects.create(actor=setup["admin"], action=Action.ADVISORY_CREATED)
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:audit") + "?actor=alice").content.decode()
    assert reverse("admin_console:audit") in body
    assert ">Clear<" in body.replace("\n", "") or "Clear" in body


# ----- Top nav says "Admin Console" -------------------------------------


@pytest.mark.django_db
def test_topnav_says_admin_console_for_admin(client, setup):
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list")).content.decode()
    assert "Admin Console" in body
    # And the href must point to /admin/, not /dashboard/.
    assert 'href="/admin/"' in body


@pytest.mark.django_db
def test_topnav_hides_admin_console_for_member(client, setup):
    client.force_login(setup["member"])
    body = client.get(reverse("advisories:list")).content.decode()
    assert "Admin Console" not in body


# ----- Publications page ------------------------------------------------


@pytest.mark.django_db
def test_publications_page_lists_failed(client, setup):
    PublicationTask.objects.create(
        advisory=setup["advisory"],
        version=setup["advisory"].versions.get(version=1),
        enqueued_by=setup["admin"],
        status=PublicationTaskStatus.FAILED,
        last_error="boom",
    )
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:publications")).content.decode()
    assert "Failed publication exports" in body
    assert "boom" in body


@pytest.mark.django_db
def test_publications_page_lists_awaiting_republish(client, setup):
    """Republish-required advisories appear under "Awaiting re-publication";
    GHSA-linked rows are excluded (they auto-re-publish, INV-GHSA-3)."""
    adv = Advisory.objects.create(
        project=setup["project"],
        summary="edited since publish",
        state=State.PUBLISHED,
        republish_required=True,
    )
    Advisory.objects.create(
        project=setup["project"],
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        ghsa_owner="eclipse",
        ghsa_repo="widget",
        state=State.PUBLISHED,
        republish_required=True,
    )
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:publications"))
    body = response.content.decode()
    assert "Awaiting re-publication" in body
    assert adv.advisory_id in body
    awaiting_ids = {a.advisory_id for a in response.context["awaiting_republish"]}
    assert awaiting_ids == {adv.advisory_id}


@pytest.mark.django_db
def test_publications_page_failed_republish_only_in_failed_section(client, setup):
    """A failed re-publish (FAILED task + republish_required) is deduped out of
    "Awaiting re-publication" — it belongs to the failed-exports section."""
    adv = Advisory.objects.create(
        project=setup["project"],
        summary="x",
        state=State.PUBLISHED,
        republish_required=True,
    )
    PublicationTask.objects.create(
        advisory=adv,
        version=adv.versions.get(version=1),
        enqueued_by=setup["admin"],
        status=PublicationTaskStatus.FAILED,
        last_error="boom",
    )
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:publications"))
    assert adv not in response.context["awaiting_republish"]
    assert adv in [t.advisory for t in response.context["failed_publications"]]


# ----- Access-log browser -----------------------------------------------


@pytest.mark.django_db
def test_access_log_403_for_non_admin(client, setup):
    client.force_login(setup["member"])
    assert client.get(reverse("admin_console:access_log")).status_code == 403


@pytest.mark.django_db
def test_access_log_lists_ephemeral_events(client, setup):
    from audit.services import record

    record(action=Action.ADVISORY_VIEWED, actor=setup["admin"], advisory=setup["advisory"])
    client.force_login(setup["admin"])
    resp = client.get(reverse("admin_console:access_log"))
    assert resp.status_code == 200
    assert Action.ADVISORY_VIEWED in _audit_table(resp.content.decode())


@pytest.mark.django_db
def test_access_log_action_filter_offers_only_ephemeral_actions(client, setup):
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:access_log")).content.decode()
    assert f'value="{Action.ADVISORY_VIEWED}"' in body  # ephemeral → offered
    assert f'value="{Action.ADVISORY_CREATED}"' not in body  # ledger → not offered


@pytest.mark.django_db
def test_access_log_q_filters_metadata(client, setup):
    from audit.services import record

    record(action=Action.GHSA_METADATA_FETCHED, actor=setup["admin"], metadata={"needle": "abc123"})
    record(action=Action.ADVISORY_VIEWED, actor=setup["admin"], metadata={"other": "zzz"})
    client.force_login(setup["admin"])
    table = _audit_table(
        client.get(reverse("admin_console:access_log") + "?q=abc123").content.decode()
    )
    assert Action.GHSA_METADATA_FETCHED in table
    assert Action.ADVISORY_VIEWED not in table


# ----- CVE-request ban / allow (INV-CVE-3) -------------------------------


@pytest.mark.django_db
def test_cves_page_lists_banned_advisory(client, setup):
    setup["advisory"].cve_requests_banned = True
    setup["advisory"].save(update_fields=["cve_requests_banned"])
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:cves")).content.decode()
    assert f"cve-banned-{setup['advisory'].pk}" in body
    assert "Allow CVE requests" in body


@pytest.mark.django_db
def test_cve_allow_clears_ban_and_drops_from_list(client, setup):
    setup["advisory"].cve_requests_banned = True
    setup["advisory"].save(update_fields=["cve_requests_banned"])
    client.force_login(setup["admin"])
    url = reverse("admin_console:cve_allow", args=[setup["advisory"].advisory_id])

    resp = client.post(url)
    assert resp.status_code == 200
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].cve_requests_banned is False
    assert AuditLogEntry.objects.filter(action=Action.CVE_REQUEST_UNBANNED).exists()

    # The advisory no longer appears in the banned section on reload.
    body = client.get(reverse("admin_console:cves")).content.decode()
    assert f"cve-banned-{setup['advisory'].pk}" not in body
    assert "No advisories have CVE requests banned." in body


@pytest.mark.django_db
def test_cve_allow_requires_admin(client, setup):
    setup["advisory"].cve_requests_banned = True
    setup["advisory"].save(update_fields=["cve_requests_banned"])
    client.force_login(setup["member"])
    url = reverse("admin_console:cve_allow", args=[setup["advisory"].advisory_id])
    assert client.post(url).status_code == 403
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].cve_requests_banned is True


@pytest.mark.django_db
def test_cve_allow_rejects_get(client, setup):
    client.force_login(setup["admin"])
    url = reverse("admin_console:cve_allow", args=[setup["advisory"].advisory_id])
    assert client.get(url).status_code == 405
