"""Withdrawal-request queue (INV-WITHDRAW).

A non-mature project owner can't withdraw a published advisory directly
(`can_withdraw_published` is mature-publisher/admin only), so they request one
that an admin fulfils via `withdraw_advisory`. Mirrors the draft
reassignment-request pattern.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from advisories import permissions as perms
from advisories import services
from advisories.models import Advisory, State
from audit.models import Action, AuditLogEntry


@pytest.fixture
def admin_user(db, make_user, admin_group):
    return make_user(email="admin@example.org", groups=[admin_group.name])


def _published(project, **kwargs):
    return Advisory.objects.create(project=project, state=State.PUBLISHED, summary="x", **kwargs)


# -------------------- Permissions --------------------------------------------


def test_can_request_withdrawal_non_mature_owner(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    assert perms.can_request_withdrawal(member, _published(project)) is True


def test_cannot_request_withdrawal_mature_owner(db, make_user, make_project):
    project = make_project("alpha", is_mature_publisher=True)
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    # Mature-publisher owners withdraw directly — they don't request.
    assert perms.can_request_withdrawal(member, _published(project)) is False


def test_cannot_request_withdrawal_admin(db, admin_user, make_project):
    assert perms.can_request_withdrawal(admin_user, _published(make_project("alpha"))) is False


def test_cannot_request_withdrawal_when_not_published(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = Advisory.objects.create(project=project, state=State.DRAFT, summary="x")
    assert perms.can_request_withdrawal(member, adv) is False


def test_cannot_request_withdrawal_when_pending(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _published(project)
    services.request_withdrawal(adv, by=member, note="dup")
    adv.refresh_from_db()
    assert perms.can_request_withdrawal(member, adv) is False


def test_can_approve_withdrawal_admin_only(db, admin_user, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _published(project)
    services.request_withdrawal(adv, by=member, note="dup")
    adv.refresh_from_db()
    assert perms.can_approve_withdrawal(admin_user, adv) is True
    assert perms.can_approve_withdrawal(member, adv) is False


def test_can_cancel_withdrawal_request(db, admin_user, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    outsider = make_user(email="o@example.org")
    adv = _published(project)
    services.request_withdrawal(adv, by=member, note="dup")
    adv.refresh_from_db()
    assert perms.can_cancel_withdrawal_request(member, adv) is True
    assert perms.can_cancel_withdrawal_request(admin_user, adv) is True
    assert perms.can_cancel_withdrawal_request(outsider, adv) is False


# -------------------- Services -----------------------------------------------


def test_request_withdrawal_sets_fields_and_audits(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _published(project)
    services.request_withdrawal(adv, by=member, note="duplicate of Y")
    adv.refresh_from_db()
    assert adv.withdrawal_requested_at is not None
    assert adv.withdrawal_requested_by == member
    assert adv.withdrawal_request_note == "duplicate of Y"
    assert AuditLogEntry.objects.filter(
        action=Action.ADVISORY_WITHDRAWAL_REQUESTED, advisory=adv
    ).exists()


def test_request_withdrawal_requires_note(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    with pytest.raises(ValueError):
        services.request_withdrawal(_published(project), by=member, note="   ")


def test_request_withdrawal_refuses_unauthorized(db, admin_user, make_project):
    with pytest.raises(PermissionDenied):
        services.request_withdrawal(_published(make_project("alpha")), by=admin_user, note="x")


def test_cancel_withdrawal_request_clears(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _published(project)
    services.request_withdrawal(adv, by=member, note="dup")
    services.cancel_withdrawal_request(adv, by=member, note="never mind")
    adv.refresh_from_db()
    assert adv.withdrawal_requested_at is None
    assert AuditLogEntry.objects.filter(
        action=Action.ADVISORY_WITHDRAWAL_REQUEST_CLEARED, advisory=adv
    ).exists()


# -------------------- Views --------------------------------------------------


def test_request_withdrawal_view(db, client, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _published(project)
    client.force_login(member)
    resp = client.post(
        reverse("advisories:request_withdrawal", args=[adv.advisory_id]), {"note": "dup"}
    )
    assert resp.status_code in (301, 302)
    adv.refresh_from_db()
    assert adv.withdrawal_requested_at is not None


def test_approve_withdrawal_view_uses_note_and_clears_request(
    db, client, admin_user, make_user, make_project
):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _published(project)
    services.request_withdrawal(adv, by=member, note="dup of Z")
    client.force_login(admin_user)
    resp = client.post(reverse("advisories:approve_withdrawal", args=[adv.advisory_id]))
    assert resp.status_code in (301, 302)
    adv.refresh_from_db()
    # The request note became the withdrawal reason, and the request is cleared.
    assert adv.withdrawn_reason == "dup of Z"
    assert adv.withdrawal_requested_at is None


def test_request_withdrawal_view_forbidden_for_mature_owner(db, client, make_user, make_project):
    project = make_project("alpha", is_mature_publisher=True)
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _published(project)
    client.force_login(member)
    resp = client.post(
        reverse("advisories:request_withdrawal", args=[adv.advisory_id]), {"note": "dup"}
    )
    assert resp.status_code == 403


def test_withdrawal_request_appears_in_admin_inbox(db, client, admin_user, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _published(project)
    services.request_withdrawal(adv, by=member, note="dup")
    client.force_login(admin_user)
    resp = client.get(reverse("admin_console:index"))
    assert resp.status_code == 200
    assert adv.advisory_id in resp.content.decode()
