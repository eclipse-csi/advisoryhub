"""Ban / unban services + enforcement (INV-AUTH-8).

A ban disables an account locally through the inherited ``is_active`` flag:
the OIDC callback view refuses a new login and
``AdvisoryHubOIDCBackend.get_user`` drops a *live* session on the next request.
These tests cover the service state transitions, the backend override, and the
end-to-end session kill (no OIDC mocking — ``force_login`` selects the OIDC
backend, the first one exposing ``get_user``).
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from accounts.auth import AdvisoryHubOIDCBackend
from accounts.services import ban_user, unban_user


@pytest.mark.django_db
def test_ban_user_sets_metadata_and_disables(make_user):
    admin = make_user(email="admin@example.org")
    target = make_user(email="t@example.org")
    assert target.is_active is True
    assert target.is_banned is False

    changed = ban_user(target, by=admin, reason="compromised")
    target.refresh_from_db()

    assert changed is True
    assert target.is_banned is True
    assert target.is_active is False
    assert target.banned_by_id == admin.pk
    assert target.ban_reason == "compromised"
    assert target.banned_at is not None


@pytest.mark.django_db
def test_ban_user_is_idempotent(make_user):
    admin = make_user(email="admin@example.org")
    target = make_user(email="t@example.org")
    assert ban_user(target, by=admin, reason="first") is True
    first_at = target.banned_at

    # A second ban no-ops: returns False and leaves the original metadata intact.
    assert ban_user(target, by=admin, reason="second") is False
    target.refresh_from_db()
    assert target.ban_reason == "first"
    assert target.banned_at == first_at


@pytest.mark.django_db
def test_unban_user_clears_metadata_and_enables(make_user):
    admin = make_user(email="admin@example.org")
    target = make_user(email="t@example.org")
    ban_user(target, by=admin, reason="oops")

    previous = unban_user(target, by=admin)
    target.refresh_from_db()

    assert previous == "oops"
    assert target.is_banned is False
    assert target.is_active is True
    assert target.banned_by_id is None
    assert target.ban_reason == ""
    assert target.banned_at is None


@pytest.mark.django_db
def test_unban_user_noop_returns_none(make_user):
    admin = make_user(email="admin@example.org")
    target = make_user(email="t@example.org")
    assert unban_user(target, by=admin) is None


@pytest.mark.django_db
def test_backend_get_user_drops_banned(make_user):
    admin = make_user(email="admin@example.org")
    target = make_user(email="t@example.org")
    backend = AdvisoryHubOIDCBackend()

    assert backend.get_user(target.pk) is not None
    ban_user(target, by=admin, reason="x")
    assert backend.get_user(target.pk) is None

    unban_user(target, by=admin)
    assert backend.get_user(target.pk) is not None


@pytest.mark.django_db
def test_banned_user_live_session_is_dropped(client, make_user):
    admin = make_user(email="admin@example.org")
    user = make_user(email="t@example.org")
    client.force_login(user)

    # A login-gated page works while the session is live.
    assert client.get(reverse("advisories:list")).status_code == 200

    ban_user(user, by=admin, reason="x")

    # Next request: get_user returns None, the user is anonymous, login_required
    # bounces them. The ban took effect mid-session with no re-login.
    assert client.get(reverse("advisories:list")).status_code == 302
