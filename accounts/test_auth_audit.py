"""Authentication events land in the ephemeral access log.

Login / step-up / logout / failed-login each write one
:class:`audit.models.AccessLogEntry` (never the durable ledger). The
``user_logged_in`` signal is sent manually here because ``client.force_login``
does not fire it (only the real ``login`` flow does); this mirrors
``test_step_up.py::test_login_signal_records_step_up_only_when_pending``.
"""

from __future__ import annotations

import pytest
from django.contrib.auth.signals import user_logged_in

from accounts.step_up import STEP_UP_AGE_KEY, STEP_UP_FLAG_KEY
from audit.models import AccessLogEntry, Action, AuditLogEntry


@pytest.mark.django_db
def test_login_records_auth_login_in_access_log(make_user, rf):
    user = make_user(email="login@example.org")
    request = rf.get("/")
    request.session = {}

    user_logged_in.send(sender=type(user), request=request, user=user)

    entry = AccessLogEntry.objects.get(action=Action.AUTH_LOGIN, actor=user)
    assert entry.ip_address == "127.0.0.1"  # RequestFactory's default REMOTE_ADDR
    # Ephemeral by design — nothing in the durable ledger.
    assert not AuditLogEntry.objects.filter(action=Action.AUTH_LOGIN).exists()


@pytest.mark.django_db
def test_step_up_reauth_records_step_up_completed_and_stamps_session(make_user, rf):
    user = make_user(email="stepup@example.org")
    request = rf.get("/")
    request.session = {STEP_UP_FLAG_KEY: True}

    user_logged_in.send(sender=type(user), request=request, user=user)

    # The existing step-up timestamp behaviour is preserved (flag consumed).
    assert STEP_UP_AGE_KEY in request.session
    assert STEP_UP_FLAG_KEY not in request.session
    # A step-up re-auth is audited as such, not as an ordinary login.
    assert AccessLogEntry.objects.filter(action=Action.AUTH_STEP_UP_COMPLETED, actor=user).exists()
    assert not AccessLogEntry.objects.filter(action=Action.AUTH_LOGIN, actor=user).exists()


@pytest.mark.django_db
def test_logout_records_auth_logout_in_access_log(client, make_user):
    user = make_user(email="logout@example.org")
    # NB: force_login DOES fire user_logged_in (→ an auth.login row); that is
    # correct (a login is a login). This test only cares about the logout row.
    client.force_login(user)

    client.logout()  # fires user_logged_out with the resolved user

    assert AccessLogEntry.objects.filter(action=Action.AUTH_LOGOUT, actor=user).exists()
    # Ephemeral by design — nothing in the durable ledger.
    assert not AuditLogEntry.objects.filter(action=Action.AUTH_LOGOUT).exists()


@pytest.mark.django_db
def test_failed_login_records_auth_login_failed(rf):
    from accounts.auth import AdvisoryHubOIDCCallbackView

    # Query params must be passed as data, not embedded in the path — the
    # RequestFactory wipes a path-embedded query string with the empty data dict.
    request = rf.get(
        "/oidc/callback/",
        {"error": "access_denied", "error_description": "denied by user"},
    )
    view = AdvisoryHubOIDCCallbackView()
    view.request = request

    response = view.login_failure()

    assert response.status_code == 302  # library redirect still happens
    entry = AccessLogEntry.objects.get(action=Action.AUTH_LOGIN_FAILED)
    assert entry.actor is None  # no identity on a failed sign-in
    assert entry.metadata["error"] == "access_denied"
    assert "denied" in entry.metadata["error_description"]
    assert not AuditLogEntry.objects.filter(action=Action.AUTH_LOGIN_FAILED).exists()
