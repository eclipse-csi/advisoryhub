"""GitHub App client tests.

The HTTP layer is mocked via the ``responses`` library; we don't make
real network calls. The tests assert the JWT shape, the
installation-token caching, and pagination link traversal.
"""

from __future__ import annotations

import jwt
import pytest
import responses

from ghsa.client import GitHubApiError, get_client


@pytest.fixture
def client(ghsa_settings):
    return get_client()


@responses.activate
def test_get_advisory_returns_payload(client):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/eclipse/example/security-advisories/GHSA-abcd-1234-efgh",
        json={"ghsa_id": "GHSA-abcd-1234-efgh", "summary": "x"},
        status=200,
    )
    payload = client.get_advisory("eclipse", "example", "GHSA-abcd-1234-efgh")
    assert payload["ghsa_id"] == "GHSA-abcd-1234-efgh"


@responses.activate
def test_get_advisory_404_returns_none(client):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/eclipse/example/security-advisories/GHSA-deleted",
        json={"message": "Not Found"},
        status=404,
    )
    assert client.get_advisory("eclipse", "example", "GHSA-deleted") is None


@responses.activate
def test_installation_token_is_cached(client):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_first", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/eclipse/r/security-advisories/GHSA-1111-1111-1111",
        json={"ghsa_id": "GHSA-1111-1111-1111"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/eclipse/r/security-advisories/GHSA-2222-2222-2222",
        json={"ghsa_id": "GHSA-2222-2222-2222"},
        status=200,
    )
    client.get_advisory("eclipse", "r", "GHSA-1111-1111-1111")
    client.get_advisory("eclipse", "r", "GHSA-2222-2222-2222")
    # Exactly one access-token mint call across two API calls.
    token_calls = [c for c in responses.calls if c.request.url.endswith("/access_tokens")]
    assert len(token_calls) == 1


@responses.activate
def test_update_advisory_cve_patches(client):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.PATCH,
        "https://api.github.com/repos/eclipse/r/security-advisories/GHSA-1234-5678-90ab",
        json={"ghsa_id": "GHSA-1234-5678-90ab", "cve_id": "CVE-2026-0001"},
        status=200,
    )
    result = client.update_advisory_cve("eclipse", "r", "GHSA-1234-5678-90ab", "CVE-2026-0001")
    assert result["cve_id"] == "CVE-2026-0001"
    patch_call = next(c for c in responses.calls if c.request.method == "PATCH")
    assert b'"cve_id": "CVE-2026-0001"' in patch_call.request.body


@responses.activate
def test_list_repo_advisories_follows_link_header(client):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/eclipse/r/security-advisories",
        json=[{"ghsa_id": "GHSA-page1-aaaa-bbbb"}],
        status=200,
        headers={
            "Link": '<https://api.github.com/repos/eclipse/r/security-advisories?page=2>; rel="next"'
        },
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/eclipse/r/security-advisories",
        json=[{"ghsa_id": "GHSA-page2-aaaa-bbbb"}],
        status=200,
    )
    items = list(client.list_repo_advisories("eclipse", "r"))
    assert [i["ghsa_id"] for i in items] == [
        "GHSA-page1-aaaa-bbbb",
        "GHSA-page2-aaaa-bbbb",
    ]


@responses.activate
def test_500_raises_after_retries(client):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    for _ in range(5):
        responses.add(
            responses.GET,
            "https://api.github.com/repos/eclipse/r/security-advisories/GHSA-aaaa-aaaa-aaaa",
            json={"message": "boom"},
            status=500,
        )
    with pytest.raises(GitHubApiError):
        client.get_advisory("eclipse", "r", "GHSA-aaaa-aaaa-aaaa")


@responses.activate
def test_create_repository_advisory_posts_payload(client):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.POST,
        "https://api.github.com/repos/eclipse/r/security-advisories",
        json={"ghsa_id": "GHSA-new1-2345-6789", "state": "draft"},
        status=201,
    )
    result = client.create_repository_advisory(
        "eclipse", "r", payload={"summary": "x", "description": "y"}
    )
    assert result["ghsa_id"] == "GHSA-new1-2345-6789"
    create_call = next(
        c
        for c in responses.calls
        if c.request.method == "POST" and "security-advisories" in c.request.url
    )
    assert b'"summary": "x"' in create_call.request.body


@responses.activate
def test_create_repository_advisory_error_raises(client):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.POST,
        "https://api.github.com/repos/eclipse/r/security-advisories",
        json={"message": "Validation failed"},
        status=422,
    )
    with pytest.raises(GitHubApiError):
        client.create_repository_advisory(
            "eclipse", "r", payload={"summary": "x", "description": "y"}
        )


@responses.activate
def test_get_private_vulnerability_reporting(client):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/eclipse/r/private-vulnerability-reporting",
        json={"enabled": True},
        status=200,
    )
    assert client.get_private_vulnerability_reporting("eclipse", "r") is True


@responses.activate
def test_get_private_vulnerability_reporting_404_is_false(client):
    responses.add(
        responses.POST,
        "https://api.github.com/app/installations/67890/access_tokens",
        json={"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"},
        status=201,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/repos/eclipse/gone/private-vulnerability-reporting",
        json={"message": "Not Found"},
        status=404,
    )
    assert client.get_private_vulnerability_reporting("eclipse", "gone") is False


def test_jwt_mint_uses_rs256(client):
    token = client._mint_app_jwt()
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    # iss must be the app id as a string.
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["iss"] == "12345"


def test_client_raises_without_config(ghsa_settings):
    from ghsa.client import reset_client_for_tests

    ghsa_settings.GITHUB_APP_ID = 0
    reset_client_for_tests()
    with pytest.raises(GitHubApiError):
        get_client()
