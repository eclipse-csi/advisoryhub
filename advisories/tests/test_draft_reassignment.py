"""Draft admin-reassignment request tests (INV-AUTH-9).

The non-locking, draft-state analogue of the triage admin-routing flag: a
project owner who finds a draft belongs to a team they're not on asks an
admin to re-home it, while the team keeps working. Covers permissions,
services, the auto-clear on every exit from draft, the HTMX views, and the
detail-page rendering gates.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.utils import timezone

from advisories import permissions as perms
from advisories import services
from advisories.models import Advisory, State
from audit.models import Action, AuditLogEntry


@pytest.fixture
def admin_user(db, make_user, admin_group):
    return make_user(email="admin@example.org", groups=[admin_group.name])


def _make_draft_advisory(project, *, created_by=None, requested_by=None, suggested_project=None):
    adv = Advisory.objects.create(
        project=project,
        state=State.DRAFT,
        summary="A vulnerability",
        details="Some details.",
        created_by=created_by,
    )
    if requested_by is not None:
        adv.reassignment_requested_at = timezone.now()
        adv.reassignment_requested_by = requested_by
        adv.reassignment_request_note = "belongs to bravo"
        adv.reassignment_suggested_project = suggested_project
        adv.save(
            update_fields=[
                "reassignment_requested_at",
                "reassignment_requested_by",
                "reassignment_request_note",
                "reassignment_suggested_project",
            ]
        )
    return adv


# -------------------- Permission predicates --------------------------------


def test_can_request_reassignment_team_member(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    assert perms.can_request_reassignment(member, adv) is True


def test_can_request_reassignment_excludes_admin(db, admin_user, make_project):
    """Admins reassign directly — they don't queue a request to themselves."""
    project = make_project("alpha")
    adv = _make_draft_advisory(project)
    assert perms.can_request_reassignment(admin_user, adv) is False


def test_can_request_reassignment_already_requested(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member)
    assert perms.can_request_reassignment(member, adv) is False


@pytest.mark.parametrize("state", [State.TRIAGE, State.PUBLISHED, State.DISMISSED])
def test_can_request_reassignment_only_in_draft(db, make_user, make_project, state):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = Advisory.objects.create(project=project, state=state, summary="x")
    assert perms.can_request_reassignment(member, adv) is False


def test_can_request_reassignment_denied_for_outsider(db, make_user, make_project):
    project = make_project("alpha")
    outsider = make_user(email="o@example.org")
    adv = _make_draft_advisory(project)
    assert perms.can_request_reassignment(outsider, adv) is False


def test_can_withdraw_reassignment_owner_and_admin(db, make_user, make_project, admin_user):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member)
    assert perms.can_withdraw_reassignment_request(member, adv) is True
    assert perms.can_withdraw_reassignment_request(admin_user, adv) is True


def test_can_withdraw_requires_pending(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)  # nothing pending
    assert perms.can_withdraw_reassignment_request(member, adv) is False


def test_request_is_non_locking(db, make_user, make_project):
    """The whole point: a pending request must not strip the team's edit
    capability (contrast the triage routing flag, INV-AUTH-6)."""
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member)
    assert perms.can_edit(member, adv) is True


# -------------------- Services ---------------------------------------------


def test_request_admin_reassignment_sets_fields(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    services.request_admin_reassignment(adv, by=member, note="belongs to bravo")
    adv.refresh_from_db()
    assert adv.reassignment_requested_at is not None
    assert adv.reassignment_requested_by == member
    assert adv.reassignment_request_note == "belongs to bravo"
    assert adv.reassignment_suggested_project_id is None  # optional, omitted here
    entry = AuditLogEntry.objects.filter(
        advisory=adv, action=Action.ADVISORY_REASSIGNMENT_REQUESTED
    ).get()
    assert entry.actor == member
    assert entry.metadata["note"] == "belongs to bravo"
    assert entry.metadata["suggested_project_slug"] == ""


def test_request_stores_suggested_project(db, make_user, make_project):
    project = make_project("alpha")
    target = make_project("bravo")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    services.request_admin_reassignment(
        adv, by=member, note="this is a bravo bug", suggested_project=target
    )
    adv.refresh_from_db()
    assert adv.reassignment_suggested_project == target
    entry = AuditLogEntry.objects.filter(
        advisory=adv, action=Action.ADVISORY_REASSIGNMENT_REQUESTED
    ).get()
    assert entry.metadata["suggested_project_slug"] == target.slug


def test_request_rejects_suggesting_current_project(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    with pytest.raises(ValueError):
        services.request_admin_reassignment(adv, by=member, note="x", suggested_project=project)


def test_request_requires_note(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    with pytest.raises(ValueError):
        services.request_admin_reassignment(adv, by=member, note="  ")


def test_request_rejected_for_admin(db, admin_user, make_project):
    project = make_project("alpha")
    adv = _make_draft_advisory(project)
    with pytest.raises(PermissionDenied):
        services.request_admin_reassignment(adv, by=admin_user, note="x")


def test_request_rejected_when_already_pending(db, make_user, make_project):
    """A second request is refused: ``can_request_reassignment`` already
    returns False once one is pending, so the permission gate fires first."""
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member)
    with pytest.raises(PermissionDenied):
        services.request_admin_reassignment(adv, by=member, note="again")


def test_withdraw_clears_fields_and_audits(db, make_user, make_project):
    project = make_project("alpha")
    target = make_project("bravo")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member, suggested_project=target)
    services.withdraw_admin_reassignment(adv, by=member, note="never mind")
    adv.refresh_from_db()
    assert adv.reassignment_requested_at is None
    assert adv.reassignment_requested_by is None
    assert adv.reassignment_request_note == ""
    assert adv.reassignment_suggested_project_id is None  # suggestion clears too
    entry = AuditLogEntry.objects.filter(
        advisory=adv, action=Action.ADVISORY_REASSIGNMENT_REQUEST_CLEARED
    ).get()
    assert entry.metadata["cause"] == "withdrawn"
    assert entry.metadata["previous_note"] == "belongs to bravo"


def test_clear_helper_is_noop_when_nothing_pending(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    assert (
        services.clear_reassignment_request_if_pending(adv, by=member, cause="published") is False
    )
    assert not AuditLogEntry.objects.filter(
        advisory=adv, action=Action.ADVISORY_REASSIGNMENT_REQUEST_CLEARED
    ).exists()


# -------------------- Auto-clear on exit from draft ------------------------


def test_dismiss_view_clears_pending_request(db, make_user, make_project, client):
    project = make_project("alpha")
    target = make_project("bravo")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member, suggested_project=target)
    client.force_login(member)
    resp = client.post(
        reverse("advisories:dismiss", args=[adv.advisory_id]),
        data={"reason": "duplicate"},
    )
    assert resp.status_code == 302
    adv.refresh_from_db()
    assert adv.state == State.DISMISSED
    assert adv.reassignment_requested_at is None
    assert adv.reassignment_suggested_project_id is None
    entry = AuditLogEntry.objects.filter(
        advisory=adv, action=Action.ADVISORY_REASSIGNMENT_REQUEST_CLEARED
    ).get()
    assert entry.metadata["cause"] == "dismissed"


# -------------------- HTMX views -------------------------------------------


def test_request_reassignment_view(db, make_user, make_project, client):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    client.force_login(member)
    resp = client.post(
        reverse("advisories:request_reassignment", args=[adv.advisory_id]),
        data={"note": "belongs to bravo"},
    )
    assert resp.status_code == 302
    adv.refresh_from_db()
    assert adv.reassignment_requested_at is not None


def test_request_reassignment_modal_get(db, make_user, make_project, admin_user, client):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    url = reverse("advisories:request_reassignment_modal", args=[adv.advisory_id])

    client.force_login(member)
    assert client.get(url).status_code == 200

    # Admin is excluded from requesting — the modal endpoint 403s for them.
    client.force_login(admin_user)
    assert client.get(url).status_code == 403


def test_withdraw_reassignment_view(db, make_user, make_project, client):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member)
    client.force_login(member)
    resp = client.post(
        reverse("advisories:withdraw_reassignment", args=[adv.advisory_id]),
        data={"note": ""},
    )
    assert resp.status_code == 302
    adv.refresh_from_db()
    assert adv.reassignment_requested_at is None


# -------------------- Detail-page rendering gates --------------------------


def test_detail_shows_request_button_for_owner(db, make_user, make_project, client):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    client.force_login(member)
    resp = client.get(reverse("advisories:detail", args=[adv.advisory_id]))
    assert resp.status_code == 200
    assert b"Request admin reassignment" in resp.content


def test_detail_renders_modal_host_for_request(db, make_user, make_project, client):
    """The request button targets ``#modal`` over HTMX, so the dialog host must
    be in the DOM on a draft for the owner. Regression: the host used to be
    rendered only for the triage routing flag (``can_flag_routing``), so a draft
    owner clicking the button hit an htmx:targetError."""
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    client.force_login(member)
    body = client.get(reverse("advisories:detail", args=[adv.advisory_id])).content.decode()
    assert 'id="modal"' in body


def test_detail_hides_request_button_for_admin(db, admin_user, make_project, client):
    project = make_project("alpha")
    adv = _make_draft_advisory(project)
    client.force_login(admin_user)
    resp = client.get(reverse("advisories:detail", args=[adv.advisory_id]))
    assert resp.status_code == 200
    assert b"Request admin reassignment" not in resp.content


def test_detail_shows_banner_when_requested(db, make_user, make_project, client):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member)
    client.force_login(member)
    resp = client.get(reverse("advisories:detail", args=[adv.advisory_id]))
    assert resp.status_code == 200
    assert b"Admin reassignment requested" in resp.content


# -------------------- Suggested target project + one-click accept ----------


def test_can_accept_suggestion_admin(db, admin_user, make_user, make_project):
    project = make_project("alpha")
    target = make_project("bravo")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member, suggested_project=target)
    assert perms.can_accept_reassignment_suggestion(admin_user, adv) is True


def test_can_accept_suggestion_requesting_member_cannot(db, make_user, make_project):
    """The requester is on the current team, not the target — so they cannot
    accept their own suggestion (that's the whole point of the escalation)."""
    project = make_project("alpha")
    target = make_project("bravo")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member, suggested_project=target)
    assert perms.can_accept_reassignment_suggestion(member, adv) is False


def test_can_accept_suggestion_owner_on_target_team(db, make_user, make_project):
    project = make_project("alpha")
    target = make_project("bravo")
    dual = make_user(
        email="d@example.org",
        groups=[f"{project.slug}-security", f"{target.slug}-security"],
    )
    adv = _make_draft_advisory(project, requested_by=dual, suggested_project=target)
    assert perms.can_accept_reassignment_suggestion(dual, adv) is True


def test_can_accept_suggestion_requires_suggestion(db, admin_user, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member)  # no suggestion
    assert perms.can_accept_reassignment_suggestion(admin_user, adv) is False


def test_can_accept_suggestion_requires_pending(db, admin_user, make_project):
    project = make_project("alpha")
    adv = _make_draft_advisory(project)  # no request pending
    assert perms.can_accept_reassignment_suggestion(admin_user, adv) is False


def test_accept_reassignment_suggestion_service(db, admin_user, make_user, make_project):
    project = make_project("alpha")
    target = make_project("bravo")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member, suggested_project=target)

    services.accept_reassignment_suggestion(adv, by=admin_user)
    adv.refresh_from_db()
    assert adv.project == target
    assert adv.reassignment_requested_at is None
    assert adv.reassignment_suggested_project_id is None
    assert adv.access_review_required_at is not None
    # project_slug is payload-visible → a version pinning the new project was appended.
    assert services.latest_version(adv).payload["project_slug"] == target.slug
    assert AuditLogEntry.objects.filter(
        advisory=adv, action=Action.ADVISORY_PROJECT_CHANGED
    ).exists()
    cleared = AuditLogEntry.objects.filter(
        advisory=adv, action=Action.ADVISORY_REASSIGNMENT_REQUEST_CLEARED
    ).get()
    assert cleared.metadata["cause"] == "accepted"


def test_accept_reassignment_view_admin(db, admin_user, make_user, make_project, client):
    project = make_project("alpha")
    target = make_project("bravo")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member, suggested_project=target)
    client.force_login(admin_user)
    resp = client.post(reverse("advisories:accept_reassignment", args=[adv.advisory_id]))
    assert resp.status_code == 302
    adv.refresh_from_db()
    assert adv.project == target
    assert adv.reassignment_requested_at is None


def test_accept_reassignment_view_denies_requesting_member(db, make_user, make_project, client):
    project = make_project("alpha")
    target = make_project("bravo")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member, suggested_project=target)
    client.force_login(member)
    resp = client.post(reverse("advisories:accept_reassignment", args=[adv.advisory_id]))
    assert resp.status_code == 403
    adv.refresh_from_db()
    assert adv.project == project  # unchanged


def test_request_modal_lists_suggestable_projects(db, make_user, make_project, client):
    project = make_project("alpha")
    target = make_project("bravo")
    # The `unsorted` sentinel is provided by projects migration 0002 — it must
    # be excluded from the picker (no need to recreate it here).
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project)
    client.force_login(member)
    resp = client.get(reverse("advisories:request_reassignment_modal", args=[adv.advisory_id]))
    assert resp.status_code == 200
    body = resp.content.decode()
    assert f'value="{target.slug}"' in body  # a sibling project is offered
    assert f'value="{project.slug}"' not in body  # current project excluded
    assert 'value="unsorted"' not in body  # sentinel excluded


def test_banner_shows_accept_for_admin(db, admin_user, make_user, make_project, client):
    project = make_project("alpha")
    target = make_project("bravo")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member, suggested_project=target)
    client.force_login(admin_user)
    body = client.get(reverse("advisories:detail", args=[adv.advisory_id])).content.decode()
    assert "Suggested target" in body
    assert "Accept — move to" in body


def test_banner_hides_accept_for_requesting_member(db, make_user, make_project, client):
    project = make_project("alpha")
    target = make_project("bravo")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_draft_advisory(project, requested_by=member, suggested_project=target)
    client.force_login(member)
    body = client.get(reverse("advisories:detail", args=[adv.advisory_id])).content.decode()
    assert "Suggested target" in body  # banner + suggestion visible to all
    assert "Accept — move to" not in body  # but the requester can't accept
