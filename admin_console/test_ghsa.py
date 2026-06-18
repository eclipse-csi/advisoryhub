"""Tests for the Admin Console GHSA operations + observability section.

Covers admin gating, the feature-flag sidebar gate, the dashboard tables,
the org-wide action endpoints (authz + feature gate + redirect target), and
the bulk CVE-push retry service/view.
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from advisories.models import Advisory, Kind
from ghsa import services as ghsa_services
from ghsa import views as ghsa_views
from ghsa.models import (
    GhsaCvePushTask,
    GhsaCvePushTaskStatus,
    GhsaSyncRun,
    GhsaSyncRunScope,
    GhsaSyncRunStatus,
    GitHubAppInstallation,
    WebhookDelivery,
    WebhookDeliveryStatus,
)

# Org-wide action endpoints reachable from the dashboard (no URL args).
ACTION_ENDPOINTS = [
    "ghsa:sync-all",
    "ghsa:sync-all-pmi",
    "ghsa:reconcile",
    "ghsa:discover",
    "ghsa:catch-up-webhooks",
    "ghsa:retry-all-cve-pushes",
]


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    settings.GHSA_FEATURE_ENABLED = True
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        ghsa_owner="eclipse",
        ghsa_repo="example",
    )
    failed_push = GhsaCvePushTask.objects.create(
        advisory=advisory,
        cve_id="CVE-2026-0001",
        status=GhsaCvePushTaskStatus.FAILED,
        last_error="boom",
        requested_by=admin,
    )
    sync_run = GhsaSyncRun.objects.create(
        scope=GhsaSyncRunScope.ALL,
        status=GhsaSyncRunStatus.PARTIAL,
        advisories_created=1,
        advisories_updated=2,
        errors_count=1,
        requested_by=admin,
    )
    delivery = WebhookDelivery.objects.create(
        delivery_id="d-test-1",
        event="repository_advisory",
        action="published",
        status=WebhookDeliveryStatus.FAILED,
        last_error="dispatch failed",
    )
    GitHubAppInstallation.objects.create(installation_id=42, account_login="eclipse")
    return {
        "admin": admin,
        "member": member,
        "advisory": advisory,
        "failed_push": failed_push,
        "sync_run": sync_run,
        "delivery": delivery,
    }


@pytest.fixture
def no_network(monkeypatch):
    """Neutralise every enqueue so action endpoints don't hit GitHub/PMI.

    In the test settings Celery runs eagerly, so an un-patched ``.delay()``
    would execute the real service inline.
    """
    for name in (
        "run_ghsa_sync_all",
        "run_pmi_repo_sync",
        "reconcile_ghsa_linked_advisories",
        "run_scheduled_ghsa_discovery",
    ):
        monkeypatch.setattr(getattr(ghsa_views, name), "delay", lambda *a, **k: None)
    monkeypatch.setattr(ghsa_services, "safe_enqueue", lambda *a, **k: None)


# ----- Dashboard gating + content ----------------------------------------


@pytest.mark.django_db
def test_dashboard_403_for_non_admin(client, setup):
    client.force_login(setup["member"])
    assert client.get(reverse("admin_console:ghsa")).status_code == 403


@pytest.mark.django_db
def test_dashboard_lists_observability_rows(client, setup):
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:ghsa")).content.decode()
    assert setup["advisory"].advisory_id in body  # failed CVE-push row
    assert "CVE-2026-0001" in body
    assert "repository_advisory" in body  # webhook delivery row
    assert "eclipse" in body  # registered installation
    assert reverse("ghsa:connect") in body  # "Configure GitHub App" link


# ----- Sidebar feature gate ----------------------------------------------


@pytest.mark.django_db
def test_sidebar_shows_ghsa_link_when_enabled(client, setup):
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:index")).content.decode()
    assert reverse("admin_console:ghsa") in body


@pytest.mark.django_db
def test_sidebar_hides_ghsa_link_when_disabled(client, setup, settings):
    settings.GHSA_FEATURE_ENABLED = False
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:index")).content.decode()
    assert reverse("admin_console:ghsa") not in body


@pytest.mark.django_db
def test_dashboard_renders_with_feature_disabled(client, setup, settings):
    """Direct URL access still works (banner + hidden operations), and the
    operation forms are not rendered while the integration is dormant."""
    settings.GHSA_FEATURE_ENABLED = False
    client.force_login(setup["admin"])
    resp = client.get(reverse("admin_console:ghsa"))
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "GHSA integration is disabled" in body
    assert reverse("ghsa:sync-all") not in body  # operation buttons hidden


# ----- Action endpoints: authz, feature gate, redirect -------------------


@pytest.mark.django_db
@pytest.mark.parametrize("endpoint", ACTION_ENDPOINTS)
def test_action_endpoint_403_for_non_admin(client, setup, no_network, endpoint):
    client.force_login(setup["member"])
    assert client.post(reverse(endpoint)).status_code == 403


@pytest.mark.django_db
def test_retry_cve_push_403_for_non_admin(client, setup, no_network):
    client.force_login(setup["member"])
    url = reverse("ghsa:retry-cve-push", args=[setup["failed_push"].pk])
    assert client.post(url).status_code == 403


@pytest.mark.django_db
@pytest.mark.parametrize("endpoint", ACTION_ENDPOINTS)
def test_action_endpoint_redirects_to_dashboard(client, setup, no_network, endpoint):
    client.force_login(setup["admin"])
    resp = client.post(reverse(endpoint))
    assert resp.status_code == 302
    assert resp.url == reverse("admin_console:ghsa")


@pytest.mark.django_db
def test_org_wide_action_blocked_when_feature_off(client, setup, settings, monkeypatch):
    settings.GHSA_FEATURE_ENABLED = False
    called = []
    monkeypatch.setattr(ghsa_views.run_ghsa_sync_all, "delay", lambda *a, **k: called.append(a))
    client.force_login(setup["admin"])
    resp = client.post(reverse("ghsa:sync-all"))
    assert resp.status_code == 302
    assert resp.url == reverse("admin_console:ghsa")
    assert called == []  # feature gate short-circuits before enqueue


# ----- Bulk CVE-push retry: service + view -------------------------------


@pytest.mark.django_db
def test_retry_all_failed_cve_pushes_service(setup, monkeypatch):
    monkeypatch.setattr(ghsa_services, "safe_enqueue", lambda *a, **k: None)
    second = GhsaCvePushTask.objects.create(
        advisory=setup["advisory"],
        cve_id="CVE-2026-0002",
        status=GhsaCvePushTaskStatus.FAILED,
        last_error="kaboom",
    )
    count = ghsa_services.retry_all_failed_cve_pushes(by=setup["admin"])
    assert count == 2
    for task in (setup["failed_push"], second):
        task.refresh_from_db()
        assert task.status == GhsaCvePushTaskStatus.QUEUED
        assert task.last_error == ""


@pytest.mark.django_db
def test_retry_all_cve_pushes_view_resets_tasks(client, setup, no_network):
    client.force_login(setup["admin"])
    resp = client.post(reverse("ghsa:retry-all-cve-pushes"))
    assert resp.status_code == 302
    assert resp.url == reverse("admin_console:ghsa")
    setup["failed_push"].refresh_from_db()
    assert setup["failed_push"].status == GhsaCvePushTaskStatus.QUEUED
    assert setup["failed_push"].last_error == ""
