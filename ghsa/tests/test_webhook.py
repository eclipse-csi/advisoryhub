"""Webhook receiver tests: signature verification, idempotency, dispatch."""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import patch

import pytest
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from advisories.models import Advisory, Kind
from audit.models import AccessLogEntry, Action
from ghsa.models import (
    GitHubAppAccountType,
    GitHubAppInstallation,
    WebhookDelivery,
    WebhookDeliveryStatus,
)
from projects.models import ProjectGitHubRepository


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def http_client():
    return Client()


# ---- signature verification -------------------------------------------------


@pytest.mark.django_db
def test_bad_signature_returns_401(http_client, ghsa_settings):
    url = reverse("ghsa:webhook")
    body = json.dumps({"action": "created"}).encode()
    resp = http_client.post(
        url,
        data=body,
        content_type="application/json",
        HTTP_X_HUB_SIGNATURE_256="sha256=ffff",
        HTTP_X_GITHUB_EVENT="installation",
        HTTP_X_GITHUB_DELIVERY="d-1",
    )
    assert resp.status_code == 401
    assert WebhookDelivery.objects.count() == 0
    # An access-log entry was still written so abuse is visible.
    assert AccessLogEntry.objects.filter(action=Action.GHSA_WEBHOOK_REJECTED).exists()


@pytest.mark.django_db
def test_missing_signature_returns_401(http_client, ghsa_settings):
    url = reverse("ghsa:webhook")
    resp = http_client.post(
        url,
        data=b"{}",
        content_type="application/json",
        HTTP_X_GITHUB_EVENT="installation",
        HTTP_X_GITHUB_DELIVERY="d-1",
    )
    assert resp.status_code == 401


@pytest.mark.django_db
def test_good_signature_creates_delivery_and_returns_202(http_client, ghsa_settings):
    url = reverse("ghsa:webhook")
    body = json.dumps({"action": "created", "installation": {"id": 1}}).encode()
    sig = _sign(ghsa_settings.GITHUB_APP_WEBHOOK_SECRET, body)
    resp = http_client.post(
        url,
        data=body,
        content_type="application/json",
        HTTP_X_HUB_SIGNATURE_256=sig,
        HTTP_X_GITHUB_EVENT="installation",
        HTTP_X_GITHUB_DELIVERY="d-1",
    )
    assert resp.status_code == 202
    assert WebhookDelivery.objects.filter(delivery_id="d-1").exists()
    assert AccessLogEntry.objects.filter(action=Action.GHSA_WEBHOOK_RECEIVED).exists()


@pytest.mark.django_db
def test_replayed_delivery_is_idempotent(http_client, ghsa_settings):
    url = reverse("ghsa:webhook")
    body = json.dumps({"action": "created", "installation": {"id": 1}}).encode()
    sig = _sign(ghsa_settings.GITHUB_APP_WEBHOOK_SECRET, body)
    headers = {
        "HTTP_X_HUB_SIGNATURE_256": sig,
        "HTTP_X_GITHUB_EVENT": "installation",
        "HTTP_X_GITHUB_DELIVERY": "d-replay",
    }
    first = http_client.post(url, data=body, content_type="application/json", **headers)
    second = http_client.post(url, data=body, content_type="application/json", **headers)
    assert first.status_code == 202
    assert second.status_code == 200
    assert WebhookDelivery.objects.filter(delivery_id="d-replay").count() == 1


# ---- dispatch ---------------------------------------------------------------


@pytest.mark.django_db
def test_installation_created_event_upserts_row(ghsa_settings):
    from ghsa import services

    delivery = WebhookDelivery.objects.create(
        delivery_id="d-install-1",
        event="installation",
        action="created",
        installation_id=42,
        status=WebhookDeliveryStatus.RECEIVED,
    )
    payload = {
        "action": "created",
        "installation": {
            "id": 42,
            "account": {"login": "new-org", "type": "Organization"},
            "app_slug": "advisoryhub",
        },
    }
    services.dispatch_webhook(delivery, payload)
    delivery.refresh_from_db()
    assert delivery.status == WebhookDeliveryStatus.PROCESSED
    assert GitHubAppInstallation.objects.filter(account_login="new-org").exists()


@pytest.mark.django_db
def test_installation_suspend_marks_row_suspended(ghsa_settings):
    from ghsa import services

    GitHubAppInstallation.objects.create(
        installation_id=42,
        account_login="will-be-suspended",
        account_type=GitHubAppAccountType.ORGANIZATION,
    )
    delivery = WebhookDelivery.objects.create(
        delivery_id="d-suspend-1",
        event="installation",
        action="suspend",
        installation_id=42,
        status=WebhookDeliveryStatus.RECEIVED,
    )
    services.dispatch_webhook(delivery, {"action": "suspend", "installation": {"id": 42}})
    row = GitHubAppInstallation.objects.get(installation_id=42)
    assert row.suspended_at is not None


@pytest.mark.django_db
def test_repository_advisory_refreshes_known_advisory(ghsa_settings, make_project):
    from ghsa import services

    project = make_project("eclipse-x")
    ProjectGitHubRepository.objects.create(
        project=project,
        owner="eclipse",
        name="example",
        last_seen_in_pmi_at=timezone.now(),
    )
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-known-aaaa-bbbb",
        ghsa_owner="eclipse",
        ghsa_repo="example",
    )
    delivery = WebhookDelivery.objects.create(
        delivery_id="d-adv-1",
        event="repository_advisory",
        action="updated",
        status=WebhookDeliveryStatus.RECEIVED,
    )
    payload = {
        "action": "updated",
        "repository_advisory": {"ghsa_id": "GHSA-known-aaaa-bbbb"},
        "repository": {"full_name": "eclipse/example"},
    }
    with patch("ghsa.services.sync_single_ghsa") as mock_sync:
        mock_sync.return_value = {"changed": ["summary"], "conflict": False}
        services.dispatch_webhook(delivery, payload)
    mock_sync.assert_called_once_with(advisory, by=None)
    delivery.refresh_from_db()
    assert delivery.status == WebhookDeliveryStatus.PROCESSED


@pytest.mark.django_db
def test_repository_advisory_auto_creates_when_repo_in_pmi(ghsa_settings, make_project):
    from ghsa import services

    project = make_project("eclipse-y")
    ProjectGitHubRepository.objects.create(
        project=project,
        owner="eclipse",
        name="brand-new",
        last_seen_in_pmi_at=timezone.now(),
    )
    delivery = WebhookDelivery.objects.create(
        delivery_id="d-adv-create-1",
        event="repository_advisory",
        action="published",
        status=WebhookDeliveryStatus.RECEIVED,
    )
    payload = {
        "action": "published",
        "repository_advisory": {"ghsa_id": "GHSA-fresh-cccc-dddd"},
        "repository": {"full_name": "eclipse/brand-new"},
    }
    with patch("ghsa.services.create_ghsa_linked_advisory") as mock_create:
        mock_create.return_value = None
        services.dispatch_webhook(delivery, payload)
    mock_create.assert_called_once()
    kwargs = mock_create.call_args.kwargs
    assert kwargs["ghsa_id"] == "GHSA-fresh-cccc-dddd"
    assert kwargs["owner"] == "eclipse"
    assert kwargs["repo"] == "brand-new"
    assert kwargs["project"] == project
    delivery.refresh_from_db()
    assert delivery.status == WebhookDeliveryStatus.PROCESSED


@pytest.mark.django_db
def test_repository_advisory_skips_when_repo_unknown(ghsa_settings):
    from ghsa import services

    delivery = WebhookDelivery.objects.create(
        delivery_id="d-unknown-1",
        event="repository_advisory",
        action="published",
        status=WebhookDeliveryStatus.RECEIVED,
    )
    payload = {
        "action": "published",
        "repository_advisory": {"ghsa_id": "GHSA-skip-aaaa-bbbb"},
        "repository": {"full_name": "outside-org/some-repo"},
    }
    with patch("ghsa.services.create_ghsa_linked_advisory") as mock_create:
        services.dispatch_webhook(delivery, payload)
    mock_create.assert_not_called()
    assert not Advisory.objects.filter(ghsa_id="GHSA-skip-aaaa-bbbb").exists()


@pytest.mark.django_db
def test_unknown_event_is_skipped(ghsa_settings):
    from ghsa import services

    delivery = WebhookDelivery.objects.create(
        delivery_id="d-ping-1",
        event="ping",
        action="",
        status=WebhookDeliveryStatus.RECEIVED,
    )
    services.dispatch_webhook(delivery, {})
    delivery.refresh_from_db()
    assert delivery.status == WebhookDeliveryStatus.SKIPPED
