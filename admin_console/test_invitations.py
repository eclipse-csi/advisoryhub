"""Tests for the admin console Invitations page (list + resend + revoke)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from access.models import PendingInvitation, Permission
from advisories.models import Advisory
from audit.models import Action, AuditLogEntry


@pytest.fixture
def base(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    project = make_project("alpha", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x", created_by=member)
    return {"admin": admin, "member": member, "project": project, "advisory": advisory}


def _pending(advisory, email="invitee@example.org", **kwargs):
    return PendingInvitation.objects.create(
        advisory=advisory, email=email, permission=Permission.VIEWER, **kwargs
    )


def _make_expired(invite):
    invite.expires_at = timezone.now() - timedelta(days=1)
    invite.save(update_fields=["expires_at"])
    return invite


# ----- Auth gate ----------------------------------------------------------


@pytest.mark.django_db
def test_list_403_for_non_admin(client, base):
    client.force_login(base["member"])
    assert client.get(reverse("admin_console:invitation_list")).status_code == 403


@pytest.mark.django_db
def test_list_200_for_admin(client, base):
    client.force_login(base["admin"])
    assert client.get(reverse("admin_console:invitation_list")).status_code == 200


@pytest.mark.django_db
def test_list_redirects_anonymous(client, base):
    assert client.get(reverse("admin_console:invitation_list")).status_code in (301, 302)


@pytest.mark.django_db
def test_resend_403_for_non_admin(client, base):
    invite = _pending(base["advisory"])
    client.force_login(base["member"])
    resp = client.post(reverse("admin_console:invitation_resend", args=[invite.pk]))
    assert resp.status_code == 403


@pytest.mark.django_db
def test_revoke_403_for_non_admin(client, base):
    invite = _pending(base["advisory"])
    client.force_login(base["member"])
    resp = client.post(reverse("admin_console:invitation_revoke", args=[invite.pk]))
    assert resp.status_code == 403
    assert PendingInvitation.objects.filter(pk=invite.pk).exists()


# ----- Sidebar nav --------------------------------------------------------


@pytest.mark.django_db
def test_sidebar_marks_invitations_active(client, base):
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:invitation_list")).content.decode()
    idx = body.find(f'href="{reverse("admin_console:invitation_list")}"')
    assert idx != -1
    assert 'aria-current="page"' in body[idx : body.find(">", idx)]


# ----- List & filters -----------------------------------------------------


@pytest.mark.django_db
def test_list_shows_pending_and_excludes_redeemed(client, base, make_user):
    _pending(base["advisory"], email="visible@example.org")
    _pending(
        base["advisory"],
        email="gone@example.org",
        redeemed_at=timezone.now(),
        redeemed_by=base["member"],
    )
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:invitation_list")).content.decode()
    table = body.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "visible@example.org" in table
    assert "gone@example.org" not in table


@pytest.mark.django_db
def test_list_status_badges(client, base):
    _pending(base["advisory"], email="fresh@example.org")
    _make_expired(_pending(base["advisory"], email="stale@example.org"))
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:invitation_list")).content.decode()
    assert "Expired" in body and "Pending" in body


@pytest.mark.django_db
def test_list_status_filter_pending_vs_expired(client, base):
    _pending(base["advisory"], email="fresh@example.org")
    _make_expired(_pending(base["advisory"], email="stale@example.org"))
    client.force_login(base["admin"])

    pending = client.get(reverse("admin_console:invitation_list") + "?status=pending")
    table = pending.content.decode().split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "fresh@example.org" in table
    assert "stale@example.org" not in table

    expired = client.get(reverse("admin_console:invitation_list") + "?status=expired")
    table = expired.content.decode().split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "stale@example.org" in table
    assert "fresh@example.org" not in table


@pytest.mark.django_db
def test_list_search_by_email(client, base):
    _pending(base["advisory"], email="alice@example.org")
    _pending(base["advisory"], email="bob@example.org")
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:invitation_list") + "?q=alice").content.decode()
    table = body.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "alice@example.org" in table
    assert "bob@example.org" not in table


@pytest.mark.django_db
def test_list_filter_by_project(client, base, make_project):
    other_project = make_project("bravo")
    other_advisory = Advisory.objects.create(
        project=other_project, summary="y", created_by=base["member"]
    )
    _pending(base["advisory"], email="alpha-invitee@example.org")
    _pending(other_advisory, email="bravo-invitee@example.org")
    client.force_login(base["admin"])
    url = reverse("admin_console:invitation_list") + f"?project={base['project'].pk}"
    table = client.get(url).content.decode().split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "alpha-invitee@example.org" in table
    assert "bravo-invitee@example.org" not in table


@pytest.mark.django_db
def test_list_invalid_project_filter_ignored(client, base):
    _pending(base["advisory"], email="keep@example.org")
    client.force_login(base["admin"])
    resp = client.get(reverse("admin_console:invitation_list") + "?project=not-a-uuid")
    assert resp.status_code == 200
    table = resp.content.decode().split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "keep@example.org" in table


# ----- Resend -------------------------------------------------------------


@pytest.mark.django_db
def test_resend_refreshes_expiry_and_audits(client, base):
    invite = _make_expired(_pending(base["advisory"], email="late@example.org"))
    client.force_login(base["admin"])
    resp = client.post(
        reverse("admin_console:invitation_resend", args=[invite.pk]), {"status": "expired"}
    )
    assert resp.status_code == 302
    invite.refresh_from_db()
    assert invite.expires_at > timezone.now()
    assert AuditLogEntry.objects.filter(action=Action.INVITATION_RESENT).exists()
    # Filter state is carried back into the redirect target.
    assert "status=expired" in resp["Location"]


@pytest.mark.django_db
def test_resend_redeemed_is_noop(client, base, make_user):
    invite = _pending(
        base["advisory"],
        email="done@example.org",
        redeemed_at=timezone.now(),
        redeemed_by=base["member"],
    )
    client.force_login(base["admin"])
    resp = client.post(reverse("admin_console:invitation_resend", args=[invite.pk]))
    assert resp.status_code == 302
    assert not AuditLogEntry.objects.filter(action=Action.INVITATION_RESENT).exists()


# ----- Revoke -------------------------------------------------------------


@pytest.mark.django_db
def test_revoke_deletes_and_audits(client, base):
    invite = _pending(base["advisory"], email="cancel-me@example.org")
    client.force_login(base["admin"])
    resp = client.post(reverse("admin_console:invitation_revoke", args=[invite.pk]))
    assert resp.status_code == 302
    assert not PendingInvitation.objects.filter(pk=invite.pk).exists()
    assert AuditLogEntry.objects.filter(action=Action.INVITATION_REVOKED).exists()
