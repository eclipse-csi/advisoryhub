"""Admin-console GDPR forget-user view.

Mirrors the actor/fixture shape of ``test_ban.py``. Covers the admin-only gate,
the self-forget guard, the required justification message, the
type-the-email-to-confirm guard, the durable ``USER_FORGOTTEN`` audit trail
(with operator + secret redaction), and the rendered controls.
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from accounts.models import User
from audit.models import Action, AuditLogEntry

ADMIN_GROUP = "advisoryhub-security"


@pytest.fixture
def actors(make_user, settings):
    settings.OIDC_ADMIN_GROUP = ADMIN_GROUP
    return {
        "admin": make_user(email="admin@example.org", groups=[ADMIN_GROUP]),
        "member": make_user(email="member@example.org"),
    }


def _forget_url(u: User) -> str:
    return reverse("admin_console:user_forget", args=[u.pk])


def _detail_url(u: User) -> str:
    return reverse("admin_console:user_detail", args=[u.pk])


def _ok_payload(target: User) -> dict[str, str]:
    return {"reason": "GDPR erasure request", "confirm_email": target.email}


# ------------------------------------------------------------------- gating


@pytest.mark.django_db
def test_forget_requires_admin(client, actors):
    client.force_login(actors["member"])
    resp = client.post(_forget_url(actors["admin"]), _ok_payload(actors["admin"]))
    assert resp.status_code == 403


@pytest.mark.django_db
def test_forget_rejects_get(client, actors):
    client.force_login(actors["admin"])
    assert client.get(_forget_url(actors["member"])).status_code == 405


# ------------------------------------------------------------------- forget


@pytest.mark.django_db
def test_admin_forgets_member_records_audit(client, actors):
    member_pk = actors["member"].pk
    client.force_login(actors["admin"])
    resp = client.post(_forget_url(actors["member"]), _ok_payload(actors["member"]), follow=True)
    assert resp.status_code == 200

    member = User.objects.get(pk=member_pk)
    assert member.email != "member@example.org"  # anonymized
    assert member.is_active is False

    entry = AuditLogEntry.objects.get(action=Action.USER_FORGOTTEN)
    assert entry.actor_id == actors["admin"].pk
    assert entry.metadata["subject_pk"] == member_pk
    assert entry.metadata["via"] == "admin_console"
    assert entry.metadata["reason"] == "GDPR erasure request"


@pytest.mark.django_db
def test_forget_requires_reason(client, actors):
    client.force_login(actors["admin"])
    client.post(
        _forget_url(actors["member"]),
        {"reason": "   ", "confirm_email": actors["member"].email},  # whitespace only
    )
    assert User.objects.get(pk=actors["member"].pk).email == "member@example.org"
    assert AuditLogEntry.objects.filter(action=Action.USER_FORGOTTEN).count() == 0


@pytest.mark.django_db
def test_forget_requires_matching_email(client, actors):
    client.force_login(actors["admin"])
    client.post(
        _forget_url(actors["member"]),
        {"reason": "GDPR", "confirm_email": "typo@example.org"},
    )
    assert User.objects.get(pk=actors["member"].pk).email == "member@example.org"
    assert AuditLogEntry.objects.filter(action=Action.USER_FORGOTTEN).count() == 0


@pytest.mark.django_db
def test_self_forget_blocked(client, actors):
    client.force_login(actors["admin"])
    client.post(_forget_url(actors["admin"]), _ok_payload(actors["admin"]))
    assert User.objects.get(pk=actors["admin"].pk).email == "admin@example.org"
    assert AuditLogEntry.objects.filter(action=Action.USER_FORGOTTEN).count() == 0


@pytest.mark.django_db
def test_forget_audit_reason_is_redacted(client, actors):
    client.force_login(actors["admin"])
    client.post(
        _forget_url(actors["member"]),
        {
            "reason": "leaked ghp_abcdefghijklmnopqrstuvwx now",
            "confirm_email": actors["member"].email,
        },
    )
    entry = AuditLogEntry.objects.get(action=Action.USER_FORGOTTEN)
    assert "ghp_" not in entry.metadata["reason"]
    assert "***" in entry.metadata["reason"]


# ------------------------------------------------------------------- display


@pytest.mark.django_db
def test_detail_shows_forget_control_for_other_user(client, actors):
    client.force_login(actors["admin"])
    body = client.get(_detail_url(actors["member"])).content.decode()
    assert "Forget this account" in body
    assert "forget-user-dialog" in body


@pytest.mark.django_db
def test_detail_hides_forget_on_own_page(client, actors):
    client.force_login(actors["admin"])
    body = client.get(_detail_url(actors["admin"])).content.decode()
    assert "You cannot forget your own account" in body
    assert "forget-user-dialog" not in body
