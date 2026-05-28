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
