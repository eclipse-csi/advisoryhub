"""Multi-installation routing: per-owner installation lookup + token cache."""

from __future__ import annotations

import pytest
import responses

from ghsa.client import GitHubApiError, get_client
from ghsa.models import GitHubAppAccountType, GitHubAppInstallation


@pytest.fixture
def two_installations(ghsa_settings):
    """Adds a second installation (eclipse-ee4j → 11111) on top of the default."""
    GitHubAppInstallation.objects.update_or_create(
        installation_id=11111,
        defaults={
            "account_login": "eclipse-ee4j",
            "account_type": GitHubAppAccountType.ORGANIZATION,
        },
    )
    return get_client()


@responses.activate
def test_routes_per_owner_uses_distinct_installation_tokens(two_installations):
    # Token-mint endpoint for the default install (eclipse → 67890).
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_eclipse", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    # Token-mint endpoint for the second install (eclipse-ee4j → 11111).
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/11111/access_tokens",
        json={"token": "ghs_ee4j", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/eclipse/jetty/security-advisories/GHSA-1111-1111-1111",
        json={"ghsa_id": "GHSA-1111-1111-1111"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/eclipse-ee4j/jersey/security-advisories/GHSA-2222-2222-2222",
        json={"ghsa_id": "GHSA-2222-2222-2222"},
        status=200,
    )

    two_installations.get_advisory("eclipse", "jetty", "GHSA-1111-1111-1111")
    two_installations.get_advisory("eclipse-ee4j", "jersey", "GHSA-2222-2222-2222")

    # Each owner caused its own installation_id's token mint — never a
    # cross-routed call.
    eclipse_mint = [
        c
        for c in responses.calls
        if c.request.url.endswith("/app/installations/67890/access_tokens")
    ]
    ee4j_mint = [
        c
        for c in responses.calls
        if c.request.url.endswith("/app/installations/11111/access_tokens")
    ]
    assert len(eclipse_mint) == 1
    assert len(ee4j_mint) == 1


@responses.activate
def test_tokens_are_cached_per_installation_id(two_installations):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_eclipse", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/11111/access_tokens",
        json={"token": "ghs_ee4j", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    for ghsa in ("GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"):
        responses.add(
            responses.GET,
            f"https://api.github.com/repos/eclipse/jetty/security-advisories/{ghsa}",
            json={"ghsa_id": ghsa},
            status=200,
        )
    for ghsa in ("GHSA-cccc-cccc-cccc", "GHSA-dddd-dddd-dddd"):
        responses.add(
            responses.GET,
            f"https://api.github.com/repos/eclipse-ee4j/jersey/security-advisories/{ghsa}",
            json={"ghsa_id": ghsa},
            status=200,
        )

    two_installations.get_advisory("eclipse", "jetty", "GHSA-aaaa-aaaa-aaaa")
    two_installations.get_advisory("eclipse", "jetty", "GHSA-bbbb-bbbb-bbbb")
    two_installations.get_advisory("eclipse-ee4j", "jersey", "GHSA-cccc-cccc-cccc")
    two_installations.get_advisory("eclipse-ee4j", "jersey", "GHSA-dddd-dddd-dddd")

    # Two calls per installation but only one token mint each.
    token_calls = [c for c in responses.calls if c.request.url.endswith("/access_tokens")]
    assert len(token_calls) == 2


@pytest.mark.django_db
def test_unregistered_owner_raises_without_env_fallback(ghsa_settings):
    client = get_client()
    with pytest.raises(GitHubApiError) as exc_info:
        client.get_advisory("not-installed", "repo", "GHSA-aaaa-bbbb-cccc")
    assert "no installation registered for 'not-installed'" in str(exc_info.value)


@pytest.mark.django_db
def test_suspended_installation_is_not_resolved(ghsa_settings):
    from django.utils import timezone

    suspended = GitHubAppInstallation.objects.create(
        installation_id=99999,
        account_login="suspended-org",
        account_type=GitHubAppAccountType.ORGANIZATION,
        suspended_at=timezone.now(),
    )
    client = get_client()
    with pytest.raises(GitHubApiError):
        client.get_advisory("suspended-org", "repo", "GHSA-aaaa-bbbb-cccc")
    # Sanity: row still exists, just suspended.
    suspended.refresh_from_db()
    assert suspended.suspended_at is not None


@responses.activate
def test_list_installations_uses_app_jwt(ghsa_settings):
    client = get_client()
    responses.add(
        responses.GET,
        "https://api.github.com/app/installations",
        json=[
            {
                "id": 1,
                "account": {"login": "eclipse", "type": "Organization"},
                "app_slug": "advisoryhub",
            },
            {
                "id": 2,
                "account": {"login": "eclipse-ee4j", "type": "Organization"},
                "app_slug": "advisoryhub",
            },
        ],
        status=200,
    )
    rows = client.list_installations()
    assert len(rows) == 2
    # Should be called with a Bearer JWT, never with a `ghs_` token.
    list_call = next(c for c in responses.calls if "/app/installations" in c.request.url)
    auth = list_call.request.headers.get("Authorization", "")
    assert auth.startswith("Bearer eyJ")
