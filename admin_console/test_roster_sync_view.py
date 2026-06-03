"""Admin Console 'Sync security team' button."""

from __future__ import annotations

import pytest
from django.urls import reverse

from projects import services as project_services


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    return {"admin": admin, "member": member, "project": project}


@pytest.mark.django_db
def test_sync_roster_forbidden_for_non_admin(client, setup):
    client.force_login(setup["member"])
    url = reverse("admin_console:project_sync_roster", args=[setup["project"].pk])
    resp = client.post(url)
    assert resp.status_code == 403


@pytest.mark.django_db
def test_sync_roster_blocked_when_flag_off(client, setup, settings, monkeypatch):
    settings.PMI_ROSTER_SYNC_ENABLED = False
    called = {"n": 0}
    monkeypatch.setattr(
        project_services,
        "sync_security_team_roster",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    client.force_login(setup["admin"])
    url = reverse("admin_console:project_sync_roster", args=[setup["project"].pk])
    resp = client.post(url, follow=True)
    assert resp.status_code == 200
    assert called["n"] == 0  # the service was never invoked


@pytest.mark.django_db
def test_sync_roster_runs_for_admin_when_enabled(client, setup, settings, monkeypatch):
    settings.PMI_ROSTER_SYNC_ENABLED = True
    called = {"project": None}

    def fake_sync(project, *, by):
        called["project"] = project
        return 3

    monkeypatch.setattr(project_services, "sync_security_team_roster", fake_sync)
    client.force_login(setup["admin"])
    url = reverse("admin_console:project_sync_roster", args=[setup["project"].pk])
    resp = client.post(url)
    assert resp.status_code == 302  # redirect back to project_edit
    assert called["project"].pk == setup["project"].pk


@pytest.mark.django_db
def test_sync_roster_get_not_allowed(client, setup):
    client.force_login(setup["admin"])
    url = reverse("admin_console:project_sync_roster", args=[setup["project"].pk])
    resp = client.get(url)
    assert resp.status_code == 405
