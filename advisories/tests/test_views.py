from __future__ import annotations

from unittest.mock import patch

import pytest
from django.urls import reverse

from advisories.models import Advisory, State
from audit.models import AccessLogEntry, Action, AuditLogEntry

FORMSET_SECTIONS = ("aliases", "cwe_ids", "references", "severity", "credits", "affected")


def empty_formsets_payload() -> dict[str, str]:
    """Management-form payload for every advisory list-formset, all empty."""
    payload: dict[str, str] = {}
    for prefix in FORMSET_SECTIONS:
        payload[f"{prefix}-TOTAL_FORMS"] = "0"
        payload[f"{prefix}-INITIAL_FORMS"] = "0"
        payload[f"{prefix}-MIN_NUM_FORMS"] = "0"
        payload[f"{prefix}-MAX_NUM_FORMS"] = "1000"
    return payload


@pytest.fixture
def admin_user(make_user, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    return make_user(email="admin@example.org", groups=["advisoryhub-security"])


@pytest.fixture
def project_a(make_project):
    return make_project("project-a")


@pytest.fixture
def member_a(make_user, project_a):
    return make_user(email="member-a@example.org", groups=[project_a.security_team.name])


@pytest.fixture
def project_b(make_project):
    return make_project("project-b")


@pytest.fixture
def outsider(make_user):
    return make_user(email="outsider@example.org")


# ---- list -----------------------------------------------------------------


@pytest.mark.django_db
def test_list_requires_login(client):
    response = client.get(reverse("advisories:list"))
    assert response.status_code in (302, 301)


@pytest.mark.django_db
def test_list_only_shows_authorized_advisories(client, member_a, outsider, project_a, project_b):
    a1 = Advisory.objects.create(project=project_a, summary="visible-marker")
    a2 = Advisory.objects.create(project=project_b, summary="other-project-only-marker")

    client.force_login(member_a)
    response = client.get(reverse("advisories:list"))
    assert response.status_code == 200
    body = response.content.decode()
    assert a1.advisory_id in body
    assert "visible-marker" in body
    assert a2.advisory_id not in body
    assert "other-project-only-marker" not in body


@pytest.mark.django_db
def test_outsider_does_not_see_published_without_grant(client, outsider, project_a):
    draft = Advisory.objects.create(project=project_a, summary="draft-marker-xyz")
    pub = Advisory.objects.create(
        project=project_a, state=State.PUBLISHED, summary="public-marker-xyz"
    )
    client.force_login(outsider)
    response = client.get(reverse("advisories:list"))
    body = response.content.decode()
    assert pub.advisory_id not in body
    assert "public-marker-xyz" not in body
    assert draft.advisory_id not in body
    assert "draft-marker-xyz" not in body


@pytest.mark.django_db
def test_list_does_not_leak_published_advisories_from_other_projects(
    client, member_a, project_a, project_b
):
    own = Advisory.objects.create(project=project_a, summary="my-team-marker")
    foreign_pub = Advisory.objects.create(
        project=project_b, state=State.PUBLISHED, summary="foreign-pub-marker"
    )
    client.force_login(member_a)
    response = client.get(reverse("advisories:list"))
    body = response.content.decode()
    assert own.advisory_id in body
    assert foreign_pub.advisory_id not in body
    assert "foreign-pub-marker" not in body


# ---- detail ---------------------------------------------------------------


@pytest.mark.django_db
def test_detail_403_for_outsider_on_draft(client, outsider, project_a):
    advisory = Advisory.objects.create(project=project_a)
    client.force_login(outsider)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_detail_records_audit_view(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a)
    client.force_login(member_a)
    client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    # Views are routed to the retention-managed access log, not the ledger.
    assert AccessLogEntry.objects.filter(action=Action.ADVISORY_VIEWED, advisory=advisory).exists()
    assert not AuditLogEntry.objects.filter(action=Action.ADVISORY_VIEWED).exists()


# ---- create ---------------------------------------------------------------


@pytest.mark.django_db
def test_create_blocked_for_user_with_no_projects(client, outsider):
    client.force_login(outsider)
    response = client.get(reverse("advisories:create"))
    assert response.status_code == 403


@pytest.mark.django_db
def test_create_form_only_lists_user_projects(client, member_a, project_a, project_b):
    client.force_login(member_a)
    response = client.get(reverse("advisories:create"))
    assert response.status_code == 200
    body = response.content.decode()
    assert project_a.name in body
    assert project_b.name not in body


@pytest.mark.django_db
def test_create_post_blocks_other_project(client, member_a, project_a, project_b):
    client.force_login(member_a)
    response = client.post(
        reverse("advisories:create"),
        data={
            "project": project_b.pk,
            "summary": "trying to escape",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    # Form's project queryset is restricted, so the form is invalid (not 403)
    # — either way, no advisory is created.
    assert not Advisory.objects.filter(project=project_b).exists()
    assert response.status_code in (200, 403)


@pytest.mark.django_db
def test_create_form_loads_for_admin_with_no_projects(client, admin_user):
    """Admins have full access regardless of project security team membership.

    The early "no creatable projects" guard is for non-admins; admins must not
    be told they're not on a project's security team — that message is
    semantically wrong for them and used to fire when the projects table
    happened to be empty.
    """
    client.force_login(admin_user)
    response = client.get(reverse("advisories:create"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_create_success_for_admin_not_on_team(client, admin_user, project_a):
    client.force_login(admin_user)
    response = client.post(
        reverse("advisories:create"),
        data={
            "project": project_a.pk,
            "summary": "admin-created",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    assert response.status_code == 302
    assert Advisory.objects.filter(summary="admin-created").exists()


@pytest.mark.django_db
def test_create_success_records_audit(client, member_a, project_a):
    client.force_login(member_a)
    response = client.post(
        reverse("advisories:create"),
        data={
            "project": project_a.pk,
            "summary": "ok",
            "details": "details here",
            **empty_formsets_payload(),
        },
    )
    assert response.status_code == 302
    advisory = Advisory.objects.get(summary="ok")
    assert advisory.created_by == member_a
    assert AuditLogEntry.objects.filter(action=Action.ADVISORY_CREATED, advisory=advisory).exists()


# ---- edit -----------------------------------------------------------------


@pytest.mark.django_db
def test_edit_blocked_for_outsider(client, outsider, project_a):
    advisory = Advisory.objects.create(project=project_a)
    client.force_login(outsider)
    response = client.get(reverse("advisories:edit", args=[advisory.advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_edit_cannot_change_project_to_unauthorized(client, member_a, project_a, project_b):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(member_a)
    response = client.post(
        reverse("advisories:edit", args=[advisory.advisory_id]),
        data={
            "project": project_b.pk,
            "summary": "x",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    advisory.refresh_from_db()
    assert advisory.project_id == project_a.pk
    # Either form rejected (200 with errors) or permission denied (403).
    assert response.status_code in (200, 403)


@pytest.mark.django_db
def test_edit_project_change_sets_access_review_flag(client, admin_user, project_a, project_b):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    assert advisory.access_review_required_at is None
    client.force_login(admin_user)
    response = client.post(
        reverse("advisories:edit", args=[advisory.advisory_id]),
        data={
            "project": project_b.pk,
            "summary": "x",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    assert response.status_code in (200, 302)
    advisory.refresh_from_db()
    assert advisory.project_id == project_b.pk
    assert advisory.access_review_required_at is not None
    assert AuditLogEntry.objects.filter(
        action=Action.ADVISORY_PROJECT_CHANGED, advisory=advisory
    ).exists()


@pytest.mark.django_db
def test_edit_records_changed_fields_in_audit_metadata(client, admin_user, project_a):
    """Editor-driven edits stamp the list of changed payload fields on the
    ``ADVISORY_EDITED`` audit row so the timeline can surface what moved.
    Regression guard for the "CWE edit looks destructive" report.
    """
    advisory = Advisory.objects.create(project=project_a, summary="old", details="d")
    client.force_login(admin_user)
    response = client.post(
        reverse("advisories:edit", args=[advisory.advisory_id]),
        data={
            "project": project_a.pk,
            "summary": "new summary",
            "details": "d",
            **empty_formsets_payload(),
        },
    )
    assert response.status_code in (200, 302)
    entry = (
        AuditLogEntry.objects.filter(action=Action.ADVISORY_EDITED, advisory=advisory)
        .order_by("-created_at")
        .first()
    )
    assert entry is not None
    assert entry.metadata.get("changed_fields") == ["summary"]


@pytest.mark.django_db
def test_edit_without_project_change_leaves_access_review_flag_alone(client, admin_user, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(admin_user)
    client.post(
        reverse("advisories:edit", args=[advisory.advisory_id]),
        data={
            "project": project_a.pk,
            "summary": "updated",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    advisory.refresh_from_db()
    assert advisory.access_review_required_at is None


@pytest.mark.django_db
def test_edit_repeated_project_change_refreshes_timestamp(client, admin_user, project_a, project_b):
    from datetime import timedelta

    from django.utils import timezone

    advisory = Advisory.objects.create(project=project_a, summary="x")
    advisory.access_review_required_at = timezone.now() - timedelta(days=1)
    advisory.save(update_fields=["access_review_required_at"])
    earlier = advisory.access_review_required_at
    client.force_login(admin_user)
    client.post(
        reverse("advisories:edit", args=[advisory.advisory_id]),
        data={
            "project": project_b.pk,
            "summary": "x",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    advisory.refresh_from_db()
    assert advisory.access_review_required_at is not None
    assert advisory.access_review_required_at > earlier


# ---- edit-driven review-approval invalidation -----------------------------


@pytest.mark.django_db
def test_edit_by_owner_invalidates_approval(client, member_a, project_a):
    from advisories.models import ReviewStatus

    advisory = Advisory.objects.create(
        project=project_a, summary="x", review_status=ReviewStatus.APPROVED
    )
    client.force_login(member_a)
    response = client.post(
        reverse("advisories:edit", args=[advisory.advisory_id]),
        data={
            "project": project_a.pk,
            "summary": "edited summary",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    assert response.status_code in (200, 302)
    advisory.refresh_from_db()
    assert advisory.review_status == ReviewStatus.NONE
    assert AuditLogEntry.objects.filter(
        action=Action.ADVISORY_REVIEW_APPROVAL_INVALIDATED, advisory=advisory
    ).exists()


@pytest.mark.django_db
def test_edit_by_mature_publisher_member_also_invalidates(client, member_a, project_a):
    """The badge drops even on mature-publisher projects; publish stays available."""
    from advisories import permissions as perms
    from advisories.models import ReviewStatus

    project_a.is_mature_publisher = True
    project_a.save()
    advisory = Advisory.objects.create(
        project=project_a, summary="x", review_status=ReviewStatus.APPROVED
    )
    client.force_login(member_a)
    client.post(
        reverse("advisories:edit", args=[advisory.advisory_id]),
        data={
            "project": project_a.pk,
            "summary": "edited",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    advisory.refresh_from_db()
    assert advisory.review_status == ReviewStatus.NONE
    # Mature-publisher still keeps publish capability via the project flag.
    assert perms.can_publish(member_a, advisory)


@pytest.mark.django_db
def test_edit_by_admin_preserves_approval(client, admin_user, project_a):
    from advisories.models import ReviewStatus

    advisory = Advisory.objects.create(
        project=project_a, summary="x", review_status=ReviewStatus.APPROVED
    )
    client.force_login(admin_user)
    client.post(
        reverse("advisories:edit", args=[advisory.advisory_id]),
        data={
            "project": project_a.pk,
            "summary": "admin edit",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    advisory.refresh_from_db()
    assert advisory.review_status == ReviewStatus.APPROVED
    assert not AuditLogEntry.objects.filter(
        action=Action.ADVISORY_REVIEW_APPROVAL_INVALIDATED, advisory=advisory
    ).exists()


@pytest.mark.django_db
def test_edit_when_not_approved_does_not_touch_review_status(client, member_a, project_a):
    from advisories.models import ReviewStatus

    for status in (
        ReviewStatus.NONE,
        ReviewStatus.SUBMITTED,
        ReviewStatus.CHANGES_REQUESTED,
    ):
        advisory = Advisory.objects.create(project=project_a, summary="x", review_status=status)
        client.force_login(member_a)
        client.post(
            reverse("advisories:edit", args=[advisory.advisory_id]),
            data={
                "project": project_a.pk,
                "summary": "edited",
                "details": "",
                **empty_formsets_payload(),
            },
        )
        advisory.refresh_from_db()
        assert advisory.review_status == status, f"failed for {status}"


@pytest.mark.django_db
def test_published_edit_by_owner_invalidates_and_flags_republish(client, member_a, project_a):
    from advisories.models import ReviewStatus

    advisory = Advisory.objects.create(
        project=project_a,
        summary="x",
        state=State.PUBLISHED,
        review_status=ReviewStatus.APPROVED,
    )
    client.force_login(member_a)
    client.post(
        reverse("advisories:edit", args=[advisory.advisory_id]),
        data={
            "project": project_a.pk,
            "summary": "post-publish edit",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    advisory.refresh_from_db()
    assert advisory.republish_required is True
    assert advisory.review_status == ReviewStatus.NONE


@pytest.mark.django_db
def test_access_review_dismiss_clears_flag_and_audits(client, member_a, project_a):
    from django.utils import timezone

    advisory = Advisory.objects.create(project=project_a, summary="x")
    advisory.access_review_required_at = timezone.now()
    advisory.save(update_fields=["access_review_required_at"])
    client.force_login(member_a)
    response = client.post(reverse("advisories:access_review_dismiss", args=[advisory.advisory_id]))
    assert response.status_code == 302
    advisory.refresh_from_db()
    assert advisory.access_review_required_at is None
    assert AuditLogEntry.objects.filter(
        action=Action.ADVISORY_ACCESS_REVIEW_DISMISSED, advisory=advisory
    ).exists()


@pytest.mark.django_db
def test_access_review_dismiss_requires_grant_permission(client, outsider, project_a):
    from django.utils import timezone

    advisory = Advisory.objects.create(project=project_a, summary="x")
    advisory.access_review_required_at = timezone.now()
    advisory.save(update_fields=["access_review_required_at"])
    client.force_login(outsider)
    response = client.post(reverse("advisories:access_review_dismiss", args=[advisory.advisory_id]))
    assert response.status_code == 403
    advisory.refresh_from_db()
    assert advisory.access_review_required_at is not None


@pytest.mark.django_db
def test_access_review_dismiss_when_already_clear_is_noop(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(member_a)
    response = client.post(reverse("advisories:access_review_dismiss", args=[advisory.advisory_id]))
    assert response.status_code == 302
    assert not AuditLogEntry.objects.filter(
        action=Action.ADVISORY_ACCESS_REVIEW_DISMISSED, advisory=advisory
    ).exists()


@pytest.mark.django_db
def test_detail_shows_access_review_banner_for_grantor(client, member_a, project_a):
    from django.utils import timezone

    advisory = Advisory.objects.create(project=project_a, summary="x")
    advisory.access_review_required_at = timezone.now()
    advisory.save(update_fields=["access_review_required_at"])
    client.force_login(member_a)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    assert response.status_code == 200
    body = response.content.decode()
    assert "advisory-banner--access-review" in body
    assert "Review access" in body


@pytest.mark.django_db
def test_detail_hides_access_review_banner_when_not_set(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(member_a)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    assert response.status_code == 200
    assert "advisory-banner--access-review" not in response.content.decode()


@pytest.mark.django_db
def test_detail_shows_request_cve_button_when_available(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x", created_by=member_a)
    client.force_login(member_a)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    body = response.content.decode()
    assert "Request a CVE Number" in body
    assert "CVE Reservation Pending" not in body
    assert "CVE Requests Disabled" not in body


@pytest.mark.django_db
def test_detail_hides_request_cve_button_from_collaborator(client, member_a, project_a, make_user):
    """Requesting a CVE is owner-only; a collaborator must not see the button.
    Regression for advisoryhub--002."""
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    advisory = Advisory.objects.create(project=project_a, summary="x", created_by=member_a)
    collaborator = make_user(email="collab-view@example.org")
    grant_to_user(advisory, collaborator, AccessPermission.COLLABORATOR, by=member_a)
    client.force_login(collaborator)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    assert "Request a CVE Number" not in response.content.decode()


@pytest.mark.django_db
def test_detail_shows_pending_label_when_request_open(client, member_a, project_a):
    from workflows import services as wf

    advisory = Advisory.objects.create(project=project_a, summary="x", created_by=member_a)
    wf.request_cve(advisory, by=member_a)
    client.force_login(member_a)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    body = response.content.decode()
    assert "CVE Reservation Pending" in body
    assert "Request a CVE Number" not in body


@pytest.mark.django_db
def test_detail_shows_assigned_cve_inline_under_summary(client, member_a, project_a):
    advisory = Advisory.objects.create(
        project=project_a,
        summary="x",
        created_by=member_a,
        assigned_cve_id="CVE-2026-0042",
    )
    client.force_login(member_a)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    body = response.content.decode()
    # The CVE is now metadata under Summary, not a header badge.
    assert "CVE-2026-0042" in body
    assert 'class="cve-assigned"' in body
    # No header badge anywhere.
    assert "badge cve-assigned" not in body
    # Request button suppressed.
    assert "Request a CVE Number" not in body


@pytest.mark.django_db
def test_detail_member_does_not_see_remove_cve_button(client, member_a, project_a):
    advisory = Advisory.objects.create(
        project=project_a,
        summary="x",
        created_by=member_a,
        assigned_cve_id="CVE-2026-0042",
    )
    client.force_login(member_a)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    body = response.content.decode()
    assert "cve-unassign-form" not in body


@pytest.mark.django_db
def test_detail_admin_sees_remove_cve_button(client, admin_user, project_a):
    advisory = Advisory.objects.create(
        project=project_a,
        summary="x",
        assigned_cve_id="CVE-2026-0042",
    )
    client.force_login(admin_user)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    body = response.content.decode()
    assert "cve-unassign-form" in body
    assert "/unassign-cve/" in body


@pytest.mark.django_db
def test_detail_shows_disabled_label_when_banned(client, member_a, project_a):
    advisory = Advisory.objects.create(
        project=project_a, summary="x", created_by=member_a, cve_requests_banned=True
    )
    client.force_login(member_a)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    body = response.content.decode()
    assert "CVE Requests Disabled" in body
    assert "Request a CVE Number" not in body


@pytest.mark.django_db
def test_detail_hides_access_review_banner_for_read_only_viewer(
    client, make_user, project_a, project_b
):
    """Users without can_grant must not see the banner — only the security team can act."""
    from django.utils import timezone

    from access.services import grant_to_user

    advisory = Advisory.objects.create(project=project_a, summary="x", state=State.PUBLISHED)
    advisory.access_review_required_at = timezone.now()
    advisory.save(update_fields=["access_review_required_at"])
    # Reader has neither security-team membership nor admin rights; an
    # explicit viewer grant is required now that publication no longer
    # implies access.
    reader = make_user(email="reader@example.org")
    grant_to_user(advisory, reader, "viewer", by=None)
    client.force_login(reader)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    assert response.status_code == 200
    assert "advisory-banner--access-review" not in response.content.decode()


@pytest.mark.django_db
def test_edit_after_publish_marks_republish_required(client, admin_user, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x", state=State.PUBLISHED)
    client.force_login(admin_user)
    client.post(
        reverse("advisories:edit", args=[advisory.advisory_id]),
        data={
            "project": project_a.pk,
            "summary": "edited after publish",
            "details": "",
            **empty_formsets_payload(),
        },
    )
    advisory.refresh_from_db()
    assert advisory.summary == "edited after publish"
    assert advisory.republish_required is True


# ---- dismiss --------------------------------------------------------------


@pytest.mark.django_db
def test_dismiss_blocked_for_outsider(client, outsider, project_a):
    advisory = Advisory.objects.create(project=project_a)
    client.force_login(outsider)
    response = client.get(reverse("advisories:dismiss", args=[advisory.advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_dismiss_published_blocked(client, admin_user, project_a):
    advisory = Advisory.objects.create(project=project_a, state=State.PUBLISHED)
    client.force_login(admin_user)
    response = client.post(
        reverse("advisories:dismiss", args=[advisory.advisory_id]),
        data={"reason": "x"},
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_dismiss_records_state_change(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a)
    client.force_login(member_a)
    client.post(
        reverse("advisories:dismiss", args=[advisory.advisory_id]),
        data={"reason": "duplicate"},
    )
    advisory.refresh_from_db()
    assert advisory.state == State.DISMISSED
    assert advisory.dismissed_reason == "duplicate"
    assert AuditLogEntry.objects.filter(
        action=Action.ADVISORY_DISMISSED, advisory=advisory
    ).exists()


@pytest.mark.django_db
def test_dismiss_blocked_for_non_admin_when_cve_assigned(client, member_a, project_a):
    from workflows.models import OrphanCve

    advisory = Advisory.objects.create(project=project_a, assigned_cve_id="CVE-2026-0042")
    client.force_login(member_a)
    response = client.post(
        reverse("advisories:dismiss", args=[advisory.advisory_id]),
        data={"reason": "false positive"},
    )
    assert response.status_code == 403
    advisory.refresh_from_db()
    # Nothing changed: still draft, still has the CVE, no orphan record.
    assert advisory.state == State.DRAFT
    assert advisory.assigned_cve_id == "CVE-2026-0042"
    assert not OrphanCve.objects.exists()


@pytest.mark.django_db
def test_dismiss_admin_with_assigned_cve_creates_orphan(client, admin_user, project_a):
    from workflows.models import OrphanCve, OrphanCveStatus

    advisory = Advisory.objects.create(project=project_a, assigned_cve_id="CVE-2026-0042")
    client.force_login(admin_user)
    client.post(
        reverse("advisories:dismiss", args=[advisory.advisory_id]),
        data={"reason": "false positive"},
    )
    advisory.refresh_from_db()
    assert advisory.state == State.DISMISSED
    assert advisory.assigned_cve_id == ""
    orphan = OrphanCve.objects.get(cve_id="CVE-2026-0042")
    assert orphan.status == OrphanCveStatus.ORPHANED
    assert orphan.unassigned_by == admin_user
    assert "Advisory dismissed" in orphan.unassign_reason
    assert "false positive" in orphan.unassign_reason
    assert orphan.previous_advisory == advisory
    assert AuditLogEntry.objects.filter(action=Action.CVE_UNASSIGNED, advisory=advisory).exists()


@pytest.mark.django_db
def test_dismiss_without_assigned_cve_does_not_create_orphan(client, member_a, project_a):
    from workflows.models import OrphanCve

    advisory = Advisory.objects.create(project=project_a)
    client.force_login(member_a)
    client.post(
        reverse("advisories:dismiss", args=[advisory.advisory_id]),
        data={"reason": "duplicate"},
    )
    advisory.refresh_from_db()
    assert advisory.state == State.DISMISSED
    assert not OrphanCve.objects.exists()


@pytest.mark.django_db
def test_dismiss_cancels_open_cve_request(client, member_a, project_a):
    from workflows import services as wf
    from workflows.models import CveRequestStatus

    advisory = Advisory.objects.create(project=project_a)
    task = wf.request_cve(advisory, by=member_a)
    client.force_login(member_a)
    client.post(
        reverse("advisories:dismiss", args=[advisory.advisory_id]),
        data={"reason": "duplicate"},
    )
    task.refresh_from_db()
    assert task.status == CveRequestStatus.CANCELLED
    assert task.finished_at is not None
    assert AuditLogEntry.objects.filter(
        action=Action.CVE_REQUEST_CANCELLED, advisory=advisory
    ).exists()


@pytest.mark.django_db
def test_detail_disables_dismiss_for_member_when_cve_assigned(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, assigned_cve_id="CVE-2026-0042")
    client.force_login(member_a)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    body = response.content.decode()
    # The active link to the dismiss view must not appear.
    assert "/dismiss/" not in body
    # Instead, the user sees a disabled Dismiss control with a blocked-state
    # help hint inside the Lifecycle sidebar card.
    assert "sidebar-card__action-hint--blocked" in body
    assert "ask an admin" in body
    assert "CVE-2026-0042" in body


@pytest.mark.django_db
def test_detail_actions_panel_renders_for_editor(client, member_a, project_a):
    """Project members see the Lifecycle and Review sidebar cards with Edit,
    Submit-for-review and the corresponding help text on a fresh draft."""
    advisory = Advisory.objects.create(project=project_a)
    client.force_login(member_a)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    body = response.content.decode()
    assert "sidebar-card--lifecycle" in body
    assert "sidebar-card--review" in body
    assert "sidebar-card__action-hint" in body
    # Header no longer carries an Edit anchor — Edit lives in the Lifecycle card only.
    assert "advisory-detail__edit" not in body
    # The Edit row's help copy is present.
    assert "Modify the advisory" in body
    # And Submit-for-review's help copy too.
    assert "Freeze the current content" in body
    # Each primary action carries its semantic color class so styling
    # regressions are caught here.
    assert "btn info" in body  # Edit
    assert 'class="success"' in body  # Submit for review


@pytest.mark.django_db
def test_detail_no_actions_panel_for_outsider_on_published(client, make_user, project_a):
    """An authenticated outsider has no view permission on a published advisory,
    so the detail view returns 403 rather than rendering any sidebar cards."""
    advisory = Advisory.objects.create(project=project_a, state=State.PUBLISHED)
    reader = make_user(email="reader@example.org")
    client.force_login(reader)
    response = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    assert response.status_code == 403


# ---- edit form: list-formset behaviour ------------------------------------


def _mgmt(prefix: str, total: int, initial: int = 0) -> dict[str, str]:
    return {
        f"{prefix}-TOTAL_FORMS": str(total),
        f"{prefix}-INITIAL_FORMS": str(initial),
        f"{prefix}-MIN_NUM_FORMS": "0",
        f"{prefix}-MAX_NUM_FORMS": "1000",
    }


@pytest.mark.django_db
def test_edit_form_renders_existing_rows(client, member_a, project_a):
    advisory = Advisory.objects.create(
        project=project_a,
        summary="x",
        aliases=["CVE-2025-1", "CVE-2025-2"],
        references=[{"type": "FIX", "url": "https://example.org/fix"}],
        affected=[
            {
                "package": {"name": "lib", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0"}, {"fixed": "1.1"}],
                    }
                ],
            }
        ],
    )
    client.force_login(member_a)
    response = client.get(reverse("advisories:edit", args=[advisory.advisory_id]))
    assert response.status_code == 200
    body = response.content.decode()
    # Initial rows rendered.
    assert 'name="aliases-0-value"' in body
    assert 'name="aliases-1-value"' in body
    assert 'value="CVE-2025-1"' in body
    assert 'name="references-0-url"' in body
    assert 'value="https://example.org/fix"' in body
    assert 'name="affected-0-package_name"' in body
    assert 'value="lib"' in body
    # Inner events formset rendered for the affected row.
    assert 'name="affected-0-events-TOTAL_FORMS"' in body
    assert 'name="affected-0-events-0-value"' in body
    # package_ecosystem input is wired to the OSV ecosystems <datalist>.
    assert 'list="osv-ecosystems"' in body
    assert '<datalist id="osv-ecosystems">' in body
    assert '<option value="Maven">' in body
    # Live client-side validation: field hooks, message slot, controller.
    assert 'data-validate="ecosystem"' in body
    assert 'data-validate="purl"' in body
    assert "data-validate-error" in body
    assert "advisoryhub-validate.js" in body
    # Outer affected empty-form template has the inner-events skeleton with
    # `__prefix__` placeholders intact so the JS can clone it into a new
    # outer row. The inner template's *content* must carry an inner-index
    # placeholder that survives outer-row cloning (see the regex in
    # static/advisoryhub-formsets.js).
    assert 'name="affected-__prefix__-events-TOTAL_FORMS"' in body
    assert "affected-__prefix__-events-__prefix__-kind" in body


@pytest.mark.django_db
def test_edit_post_adds_alias(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x", aliases=["CVE-2025-1"])
    client.force_login(member_a)
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **_mgmt("aliases", total=2, initial=1),
        "aliases-0-value": "CVE-2025-1",
        "aliases-1-value": "CVE-2025-9999",
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 0),
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 302, response.content
    advisory.refresh_from_db()
    assert advisory.aliases == ["CVE-2025-1", "CVE-2025-9999"]


@pytest.mark.django_db
def test_edit_post_deletes_alias_via_delete_flag(client, member_a, project_a):
    advisory = Advisory.objects.create(
        project=project_a, summary="x", aliases=["CVE-2025-1", "CVE-2025-2"]
    )
    client.force_login(member_a)
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **_mgmt("aliases", total=2, initial=2),
        "aliases-0-value": "CVE-2025-1",
        "aliases-0-DELETE": "on",
        "aliases-1-value": "CVE-2025-2",
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 0),
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 302
    advisory.refresh_from_db()
    assert advisory.aliases == ["CVE-2025-2"]


@pytest.mark.django_db
def test_edit_post_invalid_reference_url_rejects(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(member_a)
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 1),
        "references-0-type": "ADVISORY",
        "references-0-url": "",
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 0),
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 200
    advisory.refresh_from_db()
    assert advisory.references == []


@pytest.mark.django_db
def test_edit_post_affected_with_purl_round_trip(client, member_a, project_a):
    advisory = Advisory.objects.create(
        project=project_a,
        summary="x",
        affected=[
            {
                "package": {
                    "name": "lib",
                    "ecosystem": "Maven",
                    "purl": "pkg:maven/org.example/lib@1.0.0",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.1.0"}],
                    }
                ],
            }
        ],
    )
    client.force_login(member_a)
    response = client.get(reverse("advisories:edit", args=[advisory.advisory_id]))
    assert response.status_code == 200
    body = response.content.decode()
    assert 'name="affected-0-package_purl"' in body
    assert 'value="pkg:maven/org.example/lib@1.0.0"' in body

    # Re-submit the form unchanged; the purl must round-trip.
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", total=1, initial=1),
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "Maven",
        "affected-0-package_purl": "pkg:maven/org.example/lib@1.0.0",
        "affected-0-range_type": "ECOSYSTEM",
        "affected-0-versions": "",
        **_mgmt("affected-0-events", total=2, initial=2),
        "affected-0-events-0-kind": "introduced",
        "affected-0-events-0-value": "1.0.0",
        "affected-0-events-1-kind": "fixed",
        "affected-0-events-1-value": "1.1.0",
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 302, response.content[:1000]
    advisory.refresh_from_db()
    assert advisory.affected[0]["package"] == {
        "name": "lib",
        "ecosystem": "Maven",
        "purl": "pkg:maven/org.example/lib@1.0.0",
    }


@pytest.mark.django_db
def test_edit_post_nested_affected_one_range_two_events(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(member_a)
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 1),
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "npm",
        "affected-0-range_type": "ECOSYSTEM",
        "affected-0-versions": "",
        **_mgmt("affected-0-events", 2),
        "affected-0-events-0-kind": "introduced",
        "affected-0-events-0-value": "1.0.0",
        "affected-0-events-1-kind": "fixed",
        "affected-0-events-1-value": "1.2.0",
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 302, response.content
    advisory.refresh_from_db()
    assert advisory.affected == [
        {
            "package": {"name": "lib", "ecosystem": "npm"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.0.0"},
                        {"fixed": "1.2.0"},
                    ],
                }
            ],
        }
    ]


@pytest.mark.django_db
def test_edit_post_rejects_range_without_introduced_event(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(member_a)
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 1),
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "npm",
        "affected-0-range_type": "ECOSYSTEM",
        "affected-0-versions": "",
        **_mgmt("affected-0-events", 1),
        "affected-0-events-0-kind": "fixed",
        "affected-0-events-0-value": "1.2.0",
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    # No redirect: the form re-renders with the error.
    assert response.status_code == 200
    body = response.content.decode()
    assert "Introduced" in body
    advisory.refresh_from_db()
    # Nothing got saved.
    assert advisory.affected == []


@pytest.mark.django_db
def test_edit_post_rejects_fixed_and_last_affected_in_same_range(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(member_a)
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 1),
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "npm",
        "affected-0-range_type": "ECOSYSTEM",
        "affected-0-versions": "",
        **_mgmt("affected-0-events", 3),
        "affected-0-events-0-kind": "introduced",
        "affected-0-events-0-value": "1.0.0",
        "affected-0-events-1-kind": "fixed",
        "affected-0-events-1-value": "1.2.0",
        "affected-0-events-2-kind": "last_affected",
        "affected-0-events-2-value": "1.5.0",
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 200
    body = response.content.decode()
    assert "mutually exclusive" in body
    advisory.refresh_from_db()
    assert advisory.affected == []


@pytest.mark.django_db
def test_edit_post_empty_formsets_yield_empty_lists(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x", aliases=["CVE-2025-1"])
    client.force_login(member_a)
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **empty_formsets_payload(),
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 302
    advisory.refresh_from_db()
    assert advisory.aliases == []
    assert advisory.cwe_ids == []
    assert advisory.references == []
    assert advisory.severity == []
    assert advisory.credits == []
    assert advisory.affected == []


@pytest.mark.django_db
def test_edit_post_ubuntu_severity_uses_enum_score(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(member_a)
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 1),
        "severity-0-type": "Ubuntu",
        "severity-0-score": "",
        "severity-0-score_ubuntu": "high",
        **_mgmt("credits", 0),
        **_mgmt("affected", 0),
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 302, response.content[:1000]
    advisory.refresh_from_db()
    assert advisory.severity == [{"type": "Ubuntu", "score": "high"}]


@pytest.mark.django_db
def test_edit_post_ubuntu_severity_rejects_freeform_score(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(member_a)
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 1),
        "severity-0-type": "Ubuntu",
        "severity-0-score": "weird-vector",
        "severity-0-score_ubuntu": "",
        **_mgmt("credits", 0),
        **_mgmt("affected", 0),
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 200
    advisory.refresh_from_db()
    assert advisory.severity == []


@pytest.mark.django_db
def test_edit_form_renders_existing_ubuntu_severity(client, member_a, project_a):
    advisory = Advisory.objects.create(
        project=project_a,
        summary="x",
        severity=[{"type": "Ubuntu", "score": "medium"}],
    )
    client.force_login(member_a)
    response = client.get(reverse("advisories:edit", args=[advisory.advisory_id]))
    assert response.status_code == 200
    body = response.content.decode()
    # The Ubuntu select has medium pre-selected; the cvss text input is blank.
    import re

    assert 'name="severity-0-score_ubuntu"' in body
    assert '<option value="medium" selected>' in body
    cvss_input = re.search(r'<input[^>]*name="severity-0-score"[^>]*>', body)
    assert cvss_input is not None, "cvss score input missing"
    assert 'value=""' in cvss_input.group(0) or "value=" not in cvss_input.group(0)


@pytest.mark.django_db
def test_edit_post_cwe_value_normalised_uppercase(client, member_a, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(member_a)
    data = {
        "project": project_a.pk,
        "summary": "x",
        "details": "",
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 1),
        "cwe_ids-0-value": "cwe-79",
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 0),
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 302
    advisory.refresh_from_db()
    assert advisory.cwe_ids == ["CWE-79"]


@pytest.mark.django_db
def test_edit_round_trip_no_changes_preserves_all_fields(client, member_a, project_a):
    """Re-submitting the data the form would render must yield the same JSON.

    Multi-range advisories are explicitly exploded into one row per
    (package, range) on read, so the assembled JSON for that case
    becomes the exploded form — this test sticks to the canonical
    one-range-per-package shape.
    """
    original = {
        "aliases": ["CVE-2025-1", "GHSA-aaaa-bbbb-cccc"],
        "cwe_ids": ["CWE-79"],
        "references": [
            {"type": "ADVISORY", "url": "https://example.org/a"},
            {"type": "FIX", "url": "https://example.org/fix"},
        ],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "credits": [{"name": "Alice", "type": "REPORTER"}, {"name": "Bob"}],
        "affected": [
            {
                "package": {"name": "lib", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}],
                    }
                ],
            }
        ],
    }
    advisory = Advisory.objects.create(project=project_a, summary="x", **original)
    client.force_login(member_a)
    data: dict[str, str] = {
        "project": str(project_a.pk),
        "summary": "x",
        "details": "",
        # Aliases
        **_mgmt("aliases", total=2, initial=2),
        "aliases-0-value": "CVE-2025-1",
        "aliases-1-value": "GHSA-aaaa-bbbb-cccc",
        # CWE
        **_mgmt("cwe_ids", total=1, initial=1),
        "cwe_ids-0-value": "CWE-79",
        # References
        **_mgmt("references", total=2, initial=2),
        "references-0-type": "ADVISORY",
        "references-0-url": "https://example.org/a",
        "references-1-type": "FIX",
        "references-1-url": "https://example.org/fix",
        # Severity
        **_mgmt("severity", total=1, initial=1),
        "severity-0-type": "CVSS_V3",
        "severity-0-score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        # Credits
        **_mgmt("credits", total=2, initial=2),
        "credits-0-name": "Alice",
        "credits-0-type": "REPORTER",
        "credits-1-name": "Bob",
        "credits-1-type": "",
        # Affected
        **_mgmt("affected", total=1, initial=1),
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "npm",
        "affected-0-range_type": "ECOSYSTEM",
        "affected-0-versions": "",
        **_mgmt("affected-0-events", total=2, initial=2),
        "affected-0-events-0-kind": "introduced",
        "affected-0-events-0-value": "1.0.0",
        "affected-0-events-1-kind": "fixed",
        "affected-0-events-1-value": "1.2.0",
    }
    response = client.post(reverse("advisories:edit", args=[advisory.advisory_id]), data=data)
    assert response.status_code == 302, response.content[:2000]
    advisory.refresh_from_db()
    for field, expected in original.items():
        assert getattr(advisory, field) == expected, field


# ---- advisory_created notification firing -------------------------------


@pytest.mark.django_db(transaction=True)
def test_create_fires_advisory_created_notification(client, member_a, project_a):
    """Creating an advisory enqueues ``advisory_created`` after commit."""
    client.force_login(member_a)
    with patch("advisories.views._queue_advisory_created") as queued:
        response = client.post(
            reverse("advisories:create"),
            data={
                "project": project_a.pk,
                "summary": "n",
                "details": "",
                **empty_formsets_payload(),
            },
        )
    assert response.status_code == 302
    advisory = Advisory.objects.get(summary="n")
    queued.assert_called_once_with(advisory.pk)


@pytest.mark.django_db(transaction=True)
def test_project_reassignment_fires_advisory_created_notification(
    client, admin_user, project_a, project_b
):
    """Reassigning an advisory's project enqueues ``advisory_created`` for the new project."""
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(admin_user)
    with patch("advisories.views._queue_advisory_created") as queued:
        client.post(
            reverse("advisories:edit", args=[advisory.advisory_id]),
            data={
                "project": project_b.pk,
                "summary": "x",
                "details": "",
                **empty_formsets_payload(),
            },
        )
    advisory.refresh_from_db()
    assert advisory.project_id == project_b.pk
    queued.assert_called_once_with(advisory.pk)


@pytest.mark.django_db(transaction=True)
def test_edit_without_project_change_does_not_fire_advisory_created(client, admin_user, project_a):
    advisory = Advisory.objects.create(project=project_a, summary="x")
    client.force_login(admin_user)
    with patch("advisories.views._queue_advisory_created") as queued:
        client.post(
            reverse("advisories:edit", args=[advisory.advisory_id]),
            data={
                "project": project_a.pk,
                "summary": "x-updated",
                "details": "",
                **empty_formsets_payload(),
            },
        )
    queued.assert_not_called()
