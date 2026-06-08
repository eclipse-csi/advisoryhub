"""Admin-console ban/unban user views (INV-AUTH-8).

Mirrors the actor/fixture shape of ``test_maintenance.py``. Covers the
admin-only gate, the required reason, the self-ban guard, the
ban-another-admin emergency override, the durable audit trail (with secret
redaction), and the rendered controls/badges.
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from accounts.models import User
from accounts.services import ban_user
from audit.models import Action, AuditLogEntry

ADMIN_GROUP = "advisoryhub-security"


@pytest.fixture
def actors(make_user, settings):
    settings.OIDC_ADMIN_GROUP = ADMIN_GROUP
    return {
        "admin": make_user(email="admin@example.org", groups=[ADMIN_GROUP]),
        "admin2": make_user(email="admin2@example.org", groups=[ADMIN_GROUP]),
        "member": make_user(email="member@example.org"),
    }


def _ban_url(u: User) -> str:
    return reverse("admin_console:user_ban", args=[u.pk])


def _unban_url(u: User) -> str:
    return reverse("admin_console:user_unban", args=[u.pk])


def _detail_url(u: User) -> str:
    return reverse("admin_console:user_detail", args=[u.pk])


# ------------------------------------------------------------------- gating


@pytest.mark.django_db
def test_ban_requires_admin(client, actors):
    client.force_login(actors["member"])
    assert client.post(_ban_url(actors["admin"]), {"reason": "x"}).status_code == 403


@pytest.mark.django_db
def test_ban_rejects_get(client, actors):
    client.force_login(actors["admin"])
    assert client.get(_ban_url(actors["member"])).status_code == 405


# ------------------------------------------------------------------- ban


@pytest.mark.django_db
def test_admin_bans_member_records_audit(client, actors):
    client.force_login(actors["admin"])
    resp = client.post(_ban_url(actors["member"]), {"reason": "spamming"}, follow=True)
    assert resp.status_code == 200

    member = User.objects.get(pk=actors["member"].pk)
    assert member.is_banned is True
    assert member.is_active is False
    assert member.banned_by_id == actors["admin"].pk
    assert member.ban_reason == "spamming"

    entry = AuditLogEntry.objects.get(action=Action.USER_BANNED)
    assert entry.actor_id == actors["admin"].pk
    assert entry.metadata["target_user_id"] == member.pk
    assert entry.metadata["target_email"] == member.email
    assert entry.metadata["reason"] == "spamming"


@pytest.mark.django_db
def test_ban_requires_reason(client, actors):
    client.force_login(actors["admin"])
    client.post(_ban_url(actors["member"]), {"reason": "   "})  # whitespace only
    assert User.objects.get(pk=actors["member"].pk).is_banned is False
    assert AuditLogEntry.objects.filter(action=Action.USER_BANNED).count() == 0


@pytest.mark.django_db
def test_self_ban_blocked(client, actors):
    client.force_login(actors["admin"])
    client.post(_ban_url(actors["admin"]), {"reason": "whoops"})
    assert User.objects.get(pk=actors["admin"].pk).is_banned is False
    assert AuditLogEntry.objects.filter(action=Action.USER_BANNED).count() == 0


@pytest.mark.django_db
def test_admin_can_ban_another_admin(client, actors):
    client.force_login(actors["admin"])
    client.post(_ban_url(actors["admin2"]), {"reason": "compromised"})
    assert User.objects.get(pk=actors["admin2"].pk).is_banned is True
    assert AuditLogEntry.objects.filter(action=Action.USER_BANNED).count() == 1


@pytest.mark.django_db
def test_double_ban_records_one_entry(client, actors):
    ban_user(actors["member"], by=actors["admin"], reason="first")
    client.force_login(actors["admin"])
    client.post(_ban_url(actors["member"]), {"reason": "second"})
    # Service no-ops on the already-banned account; no second audit row.
    assert AuditLogEntry.objects.filter(action=Action.USER_BANNED).count() == 0


@pytest.mark.django_db
def test_audit_reason_is_redacted(client, actors):
    client.force_login(actors["admin"])
    client.post(
        _ban_url(actors["member"]),
        {"reason": "leaked ghp_abcdefghijklmnopqrstuvwx now"},
    )
    entry = AuditLogEntry.objects.get(action=Action.USER_BANNED)
    assert "ghp_" not in entry.metadata["reason"]
    assert "***" in entry.metadata["reason"]


# ------------------------------------------------------------------- unban


@pytest.mark.django_db
def test_admin_unbans_member_records_audit(client, actors):
    ban_user(actors["member"], by=actors["admin"], reason="temp")
    client.force_login(actors["admin"])
    client.post(_unban_url(actors["member"]))

    member = User.objects.get(pk=actors["member"].pk)
    assert member.is_banned is False
    assert member.is_active is True

    entry = AuditLogEntry.objects.get(action=Action.USER_UNBANNED)
    assert entry.metadata["target_user_id"] == member.pk
    assert entry.metadata["previous_reason"] == "temp"


@pytest.mark.django_db
def test_unban_not_banned_is_noop(client, actors):
    client.force_login(actors["admin"])
    client.post(_unban_url(actors["member"]))
    assert AuditLogEntry.objects.filter(action=Action.USER_UNBANNED).count() == 0


# ------------------------------------------------------------------- display


@pytest.mark.django_db
def test_detail_shows_ban_control_for_other_user(client, actors):
    client.force_login(actors["admin"])
    body = client.get(_detail_url(actors["member"])).content.decode()
    assert "Ban this account" in body
    assert "ban-user-dialog" in body


@pytest.mark.django_db
def test_detail_shows_banned_state_and_unban(client, actors):
    ban_user(actors["member"], by=actors["admin"], reason="noisy")
    client.force_login(actors["admin"])
    body = client.get(_detail_url(actors["member"])).content.decode()
    assert "Unban account" in body
    assert "noisy" in body  # reason surfaced
    assert "Ban this account" not in body


@pytest.mark.django_db
def test_detail_hides_ban_on_own_page(client, actors):
    client.force_login(actors["admin"])
    body = client.get(_detail_url(actors["admin"])).content.decode()
    assert "You cannot ban your own account" in body
    assert "ban-user-dialog" not in body


@pytest.mark.django_db
def test_user_list_shows_status_column(client, actors):
    ban_user(actors["member"], by=actors["admin"], reason="temp")
    client.force_login(actors["admin"])
    body = client.get(reverse("admin_console:user_list")).content.decode()
    # Both states are surfaced: a banned user (dismissed badge) and the active
    # admins (published badge).
    assert "badge state-dismissed" in body
    assert "badge state-published" in body


# ---------------------------------------------------------------- status filter

# admin2 is an active, NOT-logged-in user, so its email only appears in the
# table — never in the topbar account menu (which shows the logged-in admin).
# That makes it a reliable probe for "filtered out of the list".


@pytest.mark.django_db
def test_status_filter_banned_lists_only_banned(client, actors):
    ban_user(actors["member"], by=actors["admin"], reason="temp")
    client.force_login(actors["admin"])
    body = client.get(reverse("admin_console:user_list"), {"status": "banned"}).content.decode()
    assert actors["member"].email in body
    assert actors["admin2"].email not in body


@pytest.mark.django_db
def test_status_filter_active_excludes_banned(client, actors):
    ban_user(actors["member"], by=actors["admin"], reason="temp")
    client.force_login(actors["admin"])
    body = client.get(reverse("admin_console:user_list"), {"status": "active"}).content.decode()
    assert actors["admin2"].email in body
    assert actors["member"].email not in body


@pytest.mark.django_db
def test_status_filter_invalid_is_ignored(client, actors):
    ban_user(actors["member"], by=actors["admin"], reason="temp")
    client.force_login(actors["admin"])
    body = client.get(reverse("admin_console:user_list"), {"status": "xyz"}).content.decode()
    # Unknown value falls back to "any": both the banned member and active admin2 show.
    assert actors["member"].email in body
    assert actors["admin2"].email in body


@pytest.mark.django_db
def test_status_filter_marks_selected_option(client, actors):
    client.force_login(actors["admin"])
    body = client.get(reverse("admin_console:user_list"), {"status": "banned"}).content.decode()
    assert 'value="banned" selected' in body
