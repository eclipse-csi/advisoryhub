"""Eclipse API client tests — parses mocked responses, never makes real calls."""

from __future__ import annotations

import pytest
import responses

from projects import eclipse_api
from projects.eclipse_api import (
    EclipseApiError,
    fetch_account_email,
    fetch_project_members,
)

TOKEN_URL = "https://auth.example.org/token"


@pytest.fixture(autouse=True)
def _eclipse_settings(settings):
    settings.ECLIPSE_API_TOKEN_URL = TOKEN_URL
    settings.ECLIPSE_API_CLIENT_ID = "client-id"
    settings.ECLIPSE_API_CLIENT_SECRET = "super-secret-value"
    settings.ECLIPSE_API_SCOPE = ""
    settings.ECLIPSE_API_BASE_URL = "https://api.eclipse.org"
    settings.PMI_API_BASE_URL = "https://projects.eclipse.org/api"


def _add_token(expires_in: int = 3600):
    responses.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "tok-abc", "expires_in": expires_in, "token_type": "Bearer"},
        status=200,
    )


@responses.activate
def test_fetch_project_members_unions_roles():
    _add_token()
    responses.add(
        responses.GET,
        "https://projects.eclipse.org/api/projects/technology.jetty",
        json={
            "committers": [{"username": "alice", "fullname": "Alice A"}],
            "project_leads": [{"username": "bob", "name": "Bob B"}],
            "individual_members": ["carol", {"username": "alice"}],  # dup alice collapses
            "contributors": [{"username": "ignored"}],  # not a security-team role
        },
        status=200,
    )
    members = fetch_project_members("technology.jetty")
    usernames = {m["username"] for m in members}
    assert usernames == {"alice", "bob", "carol"}
    # display name carried through where present (bob appears in one role only)
    bob = next(m for m in members if m["username"] == "bob")
    assert bob["name"] == "Bob B"


@responses.activate
def test_fetch_project_members_handles_list_response():
    _add_token()
    responses.add(
        responses.GET,
        "https://projects.eclipse.org/api/projects/foo",
        json=[{"committers": [{"username": "x"}]}],
        status=200,
    )
    assert [m["username"] for m in fetch_project_members("foo")] == ["x"]


@responses.activate
def test_fetch_account_email_returns_and_caches():
    _add_token()
    responses.add(
        responses.GET,
        "https://api.eclipse.org/account/profile/alice",
        json={"name": "alice", "mail": "alice@eclipse.org"},
        status=200,
    )
    assert fetch_account_email("alice") == "alice@eclipse.org"
    # Second call is served from cache — no new HTTP GET to the profile endpoint.
    assert fetch_account_email("alice") == "alice@eclipse.org"
    profile_calls = [c for c in responses.calls if "account/profile" in c.request.url]
    assert len(profile_calls) == 1


@responses.activate
def test_fetch_account_email_404_is_none_not_error():
    _add_token()
    responses.add(
        responses.GET,
        "https://api.eclipse.org/account/profile/ghost",
        json={"message": "not found"},
        status=404,
    )
    assert fetch_account_email("ghost") is None


@responses.activate
def test_token_is_cached_across_calls():
    _add_token()
    responses.add(
        responses.GET,
        "https://api.eclipse.org/account/profile/a",
        json={"mail": "a@eclipse.org"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.eclipse.org/account/profile/b",
        json={"mail": "b@eclipse.org"},
        status=200,
    )
    fetch_account_email("a")
    fetch_account_email("b")
    token_calls = [c for c in responses.calls if c.request.url.startswith(TOKEN_URL)]
    assert len(token_calls) == 1  # token minted once, reused


@responses.activate
def test_401_triggers_single_token_refresh():
    # Two token mints expected: the initial one, then the forced refresh.
    _add_token()
    _add_token()
    responses.add(
        responses.GET,
        "https://api.eclipse.org/account/profile/a",
        json={"message": "unauthorized"},
        status=401,
    )
    responses.add(
        responses.GET,
        "https://api.eclipse.org/account/profile/a",
        json={"mail": "a@eclipse.org"},
        status=200,
    )
    assert fetch_account_email("a") == "a@eclipse.org"
    token_calls = [c for c in responses.calls if c.request.url.startswith(TOKEN_URL)]
    assert len(token_calls) == 2


@responses.activate
def test_missing_credentials_raises():
    # No token endpoint configured at all.
    from django.test import override_settings

    with override_settings(ECLIPSE_API_CLIENT_ID=""):
        with pytest.raises(EclipseApiError):
            fetch_project_members("foo")


@responses.activate
def test_error_message_redacts_token():
    """A 500 body echoing the bearer token must be redacted in the exception."""
    _add_token()
    responses.add(
        responses.GET,
        "https://projects.eclipse.org/api/projects/leaky",
        body="upstream error: authorization: bearer tok-abc",
        status=400,
    )
    with pytest.raises(EclipseApiError) as exc:
        fetch_project_members("leaky")
    assert "tok-abc" not in str(exc.value)


def test_eclipse_api_error_redacts_on_construction():
    err = eclipse_api.EclipseApiError("token=swordfish leaked")
    assert "swordfish" not in str(err)
