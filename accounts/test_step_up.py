from __future__ import annotations

import time

import pytest
from django.contrib.auth.signals import user_logged_in
from django.test import override_settings
from django.urls import reverse

from accounts.step_up import (
    STEP_UP_AGE_KEY,
    STEP_UP_FLAG_KEY,
    is_step_up_fresh,
)


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    project = make_project("p")
    from advisories.models import Advisory

    advisory = Advisory.objects.create(project=project, summary="x")
    return {"admin": admin, "advisory": advisory}


# ---- predicate ----------------------------------------------------------


@pytest.mark.django_db
def test_is_step_up_fresh_false_when_unset(client, setup):
    client.force_login(setup["admin"])
    request = _request_with_session(client)
    assert not is_step_up_fresh(request)


@pytest.mark.django_db
def test_is_step_up_fresh_true_within_window(client, setup, settings):
    settings.STEP_UP_MAX_AGE_SECONDS = 300
    client.force_login(setup["admin"])
    request = _request_with_session(client)
    request.session[STEP_UP_AGE_KEY] = time.time()
    assert is_step_up_fresh(request)


@pytest.mark.django_db
def test_is_step_up_fresh_false_when_stale(client, setup, settings):
    settings.STEP_UP_MAX_AGE_SECONDS = 300
    client.force_login(setup["admin"])
    request = _request_with_session(client)
    request.session[STEP_UP_AGE_KEY] = time.time() - 10_000
    assert not is_step_up_fresh(request)


@pytest.mark.django_db
def test_is_step_up_fresh_false_for_anonymous(rf):
    request = rf.get("/")
    request.session = {}
    from django.contrib.auth.models import AnonymousUser

    request.user = AnonymousUser()
    assert not is_step_up_fresh(request)


# ---- publish endpoint behavior ------------------------------------------


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_publish_redirects_to_step_up_when_stale(client, setup):
    client.force_login(setup["admin"])
    response = client.post(reverse("publication:publish", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 302
    assert reverse("step_up_initiate") in response["Location"]


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_publish_proceeds_when_step_up_fresh(client, setup, monkeypatch):
    """A fresh step-up timestamp lets the publish view through."""
    from publication import tasks as pub_tasks
    from publication.git_service import PublishResult

    monkeypatch.setattr(
        pub_tasks, "publish_files", lambda **_: PublishResult(commit_sha="x" * 40, pushed_to="main")
    )
    client.force_login(setup["admin"])
    session = client.session
    session[STEP_UP_AGE_KEY] = time.time()
    session.save()

    response = client.post(reverse("publication:publish", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 302
    assert (
        reverse("advisories:detail", args=[setup["advisory"].advisory_id]) in response["Location"]
    )


# ---- API endpoint behavior ----------------------------------------------


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_api_publish_returns_401_step_up_required(client, setup):
    client.force_login(setup["admin"])
    response = client.post(reverse("api:publish", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 401
    body = response.json()
    assert body["error"] == "step_up_required"
    assert body["step_up_url"] == reverse("step_up_initiate")


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_api_publish_proceeds_when_step_up_fresh(client, setup, monkeypatch):
    from publication import tasks as pub_tasks
    from publication.git_service import PublishResult

    monkeypatch.setattr(
        pub_tasks, "publish_files", lambda **_: PublishResult(commit_sha="x" * 40, pushed_to="main")
    )
    client.force_login(setup["admin"])
    session = client.session
    session[STEP_UP_AGE_KEY] = time.time()
    session.save()

    response = client.post(reverse("api:publish", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 202


# ---- withdrawal endpoints (Tier 1) --------------------------------------
#
# Withdrawal re-exports OSV/CSAF and pushes to the public repo, just like
# publish, so it carries the same step-up gate. We stub the heavy
# ``withdraw_advisory`` service to isolate the gate from the publish pipeline.


def _published_advisory(project):
    from advisories.models import Advisory, State

    return Advisory.objects.create(project=project, summary="pub", state=State.PUBLISHED)


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_withdraw_redirects_to_step_up_when_stale(client, setup, monkeypatch):
    called: dict = {}
    monkeypatch.setattr(
        "advisories.services.withdraw_advisory", lambda *a, **k: called.setdefault("ran", True)
    )
    adv = _published_advisory(setup["advisory"].project)
    client.force_login(setup["admin"])
    response = client.post(reverse("advisories:withdraw", args=[adv.advisory_id]), {"reason": "x"})
    assert response.status_code == 302
    assert reverse("step_up_initiate") in response["Location"]
    assert "ran" not in called  # gate fired before the withdrawal service ran


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_withdraw_proceeds_when_step_up_fresh(client, setup, monkeypatch):
    called: dict = {}
    monkeypatch.setattr(
        "advisories.services.withdraw_advisory", lambda *a, **k: called.setdefault("ran", True)
    )
    adv = _published_advisory(setup["advisory"].project)
    client.force_login(setup["admin"])
    _stamp_fresh(client)
    response = client.post(reverse("advisories:withdraw", args=[adv.advisory_id]), {"reason": "x"})
    assert reverse("step_up_initiate") not in (response.get("Location") or "")
    assert called.get("ran") is True


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_approve_withdrawal_redirects_to_step_up_when_stale(client, setup, monkeypatch):
    from django.utils import timezone

    called: dict = {}
    monkeypatch.setattr(
        "advisories.services.withdraw_advisory", lambda *a, **k: called.setdefault("ran", True)
    )
    adv = _published_advisory(setup["advisory"].project)
    adv.withdrawal_requested_at = timezone.now()
    adv.withdrawal_request_note = "please withdraw"
    adv.save(update_fields=["withdrawal_requested_at", "withdrawal_request_note"])
    client.force_login(setup["admin"])
    response = client.post(reverse("advisories:approve_withdrawal", args=[adv.advisory_id]))
    assert response.status_code == 302
    assert reverse("step_up_initiate") in response["Location"]
    assert "ran" not in called


# ---- break-glass admin endpoints (Tier 2) -------------------------------


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_user_ban_redirects_to_step_up_when_stale(client, setup, make_user):
    target = make_user(email="target@example.org")
    client.force_login(setup["admin"])
    response = client.post(reverse("admin_console:user_ban", args=[target.pk]), {"reason": "spam"})
    assert response.status_code == 302
    assert reverse("step_up_initiate") in response["Location"]


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_user_ban_proceeds_when_step_up_fresh(client, setup, make_user):
    target = make_user(email="target@example.org")
    client.force_login(setup["admin"])
    _stamp_fresh(client)
    response = client.post(reverse("admin_console:user_ban", args=[target.pk]), {"reason": "spam"})
    # Past the gate → the ban runs and redirects back to the user detail page.
    assert response["Location"] == reverse("admin_console:user_detail", args=[target.pk])


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_user_unban_redirects_to_step_up_when_stale(client, setup, make_user):
    target = make_user(email="target@example.org")
    client.force_login(setup["admin"])
    response = client.post(reverse("admin_console:user_unban", args=[target.pk]))
    assert response.status_code == 302
    assert reverse("step_up_initiate") in response["Location"]


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_user_forget_redirects_to_step_up_when_stale(client, setup, make_user):
    target = make_user(email="target@example.org")
    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:user_forget", args=[target.pk]),
        {"reason": "gdpr", "confirm_email": target.email},
    )
    assert response.status_code == 302
    assert reverse("step_up_initiate") in response["Location"]


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_user_forget_proceeds_when_step_up_fresh(client, setup, make_user):
    """A fresh step-up gets past the gate; an empty reason then bounces back
    (so the erasure never runs) — proving the gate, not the side effect."""
    target = make_user(email="target@example.org")
    client.force_login(setup["admin"])
    _stamp_fresh(client)
    response = client.post(reverse("admin_console:user_forget", args=[target.pk]), {})
    assert response["Location"] == reverse("admin_console:user_detail", args=[target.pk])


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_maintenance_post_redirects_to_step_up_when_stale(client, setup):
    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:maintenance"), {"is_enabled": "on", "message": "down"}
    )
    assert response.status_code == 302
    assert reverse("step_up_initiate") in response["Location"]


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_maintenance_post_proceeds_when_step_up_fresh(client, setup):
    client.force_login(setup["admin"])
    _stamp_fresh(client)
    response = client.post(
        reverse("admin_console:maintenance"), {"is_enabled": "on", "message": "down"}
    )
    assert response["Location"] == reverse("admin_console:maintenance")


@pytest.mark.django_db
@override_settings(STEP_UP_REQUIRED=True, STEP_UP_MAX_AGE_SECONDS=300)
def test_maintenance_get_is_not_step_up_gated(client, setup):
    """Viewing the toggle page (GET) is open; only the POST that flips it is gated."""
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:maintenance"))
    assert response.status_code == 200


# ---- signal handler ------------------------------------------------------


@pytest.mark.django_db
def test_login_signal_records_step_up_only_when_pending(client, setup, rf):
    """The user_logged_in signal handler stamps the session ONLY when the
    step_up_pending flag was set on the request session."""
    request = rf.get("/")
    request.session = {STEP_UP_FLAG_KEY: True}
    user_logged_in.send(sender=type(setup["admin"]), request=request, user=setup["admin"])
    assert STEP_UP_AGE_KEY in request.session
    assert STEP_UP_FLAG_KEY not in request.session  # consumed

    # And: an ordinary login (no pending flag) does NOT stamp.
    request2 = rf.get("/")
    request2.session = {}
    user_logged_in.send(sender=type(setup["admin"]), request=request2, user=setup["admin"])
    assert STEP_UP_AGE_KEY not in request2.session


# ---- helpers -------------------------------------------------------------


def _stamp_fresh(client):
    """Mark the test client's session as having a fresh step-up re-auth."""
    session = client.session
    session[STEP_UP_AGE_KEY] = time.time()
    session.save()


def _request_with_session(client):
    """Build an HttpRequest-shape thing with the test client's session."""
    from django.contrib.auth import get_user_model
    from django.test import RequestFactory

    rf = RequestFactory()
    req = rf.get("/")
    req.session = client.session
    User = get_user_model()
    if "_auth_user_id" in client.session:
        req.user = User.objects.get(pk=client.session["_auth_user_id"])
    else:
        from django.contrib.auth.models import AnonymousUser

        req.user = AnonymousUser()
    return req
