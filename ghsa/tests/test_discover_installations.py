"""``discover_github_installations`` management command + the underlying service."""

from __future__ import annotations

import pytest
import responses
from django.core.management import call_command

from ghsa.models import GitHubAppInstallation


@responses.activate
@pytest.mark.django_db
def test_discover_installations_upserts_rows(ghsa_settings):
    responses.add(
        responses.GET,
        "https://api.github.com/app/installations",
        json=[
            {
                "id": 100,
                "account": {"login": "eclipse-foundation", "type": "Organization"},
                "app_slug": "advisoryhub",
            },
            {
                "id": 200,
                "account": {"login": "eclipse-ee4j", "type": "Organization"},
                "app_slug": "advisoryhub",
            },
        ],
        status=200,
    )
    call_command("discover_github_installations")
    assert GitHubAppInstallation.objects.filter(account_login="eclipse-foundation").exists()
    assert GitHubAppInstallation.objects.filter(account_login="eclipse-ee4j").exists()


@responses.activate
@pytest.mark.django_db
def test_discover_installations_is_idempotent(ghsa_settings):
    payload = {
        "id": 100,
        "account": {"login": "eclipse-foundation", "type": "Organization"},
        "app_slug": "advisoryhub",
    }
    responses.add(
        responses.GET,
        "https://api.github.com/app/installations",
        json=[payload],
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.github.com/app/installations",
        json=[payload],
        status=200,
    )
    call_command("discover_github_installations")
    call_command("discover_github_installations")
    rows = GitHubAppInstallation.objects.filter(installation_id=100)
    assert rows.count() == 1
    # last_seen_at is bumped on second pass.
    assert rows.first().last_seen_at is not None
