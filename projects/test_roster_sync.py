"""Roster sync service tests — the Eclipse API is mocked at the service boundary."""

from __future__ import annotations

import pytest

from accounts.models import User
from audit.models import AccessLogEntry, Action
from projects import services
from projects.eclipse_api import EclipseApiError
from projects.models import SecurityTeamRosterEntry


def _patch_api(monkeypatch, members, emails=None):
    """Patch the Eclipse API as imported into ``projects.services``.

    ``members`` is a list of usernames; ``emails`` maps username→email
    (defaults to ``<username>@eclipse.org``; map a value to None to simulate a
    missing/failed email lookup).
    """
    emails = emails or {}

    def fake_members(slug):
        return [{"username": u, "name": u.title()} for u in members]

    def fake_email(username):
        return emails.get(username, f"{username}@eclipse.org")

    monkeypatch.setattr(services, "fetch_project_members", fake_members)
    monkeypatch.setattr(services, "fetch_account_email", fake_email)


@pytest.mark.django_db
def test_shadow_user_created_with_no_access(monkeypatch, make_project):
    project = make_project("technology.jetty")
    _patch_api(monkeypatch, ["alice"])

    active = services.sync_security_team_roster(project, by=None)

    assert active == 1
    entry = SecurityTeamRosterEntry.objects.get(project=project, eclipse_username="alice")
    assert entry.email == "alice@eclipse.org"
    shadow = entry.user
    assert shadow is not None
    assert shadow.is_provisioned is True
    # The crux of the notify-only posture: a shadow holds NO authorization.
    assert shadow.groups.count() == 0
    assert not shadow.has_usable_password()


@pytest.mark.django_db
def test_idempotent_rerun(monkeypatch, make_project):
    project = make_project("p")
    _patch_api(monkeypatch, ["alice", "bob"])
    assert services.sync_security_team_roster(project, by=None) == 2
    # Re-run: same roster → same active count, no duplicate users/rows.
    assert services.sync_security_team_roster(project, by=None) == 2
    assert SecurityTeamRosterEntry.objects.filter(project=project).count() == 2
    assert User.objects.filter(is_provisioned=True).count() == 2


@pytest.mark.django_db
def test_soft_remove_and_reactivate(monkeypatch, make_project):
    project = make_project("p")
    _patch_api(monkeypatch, ["alice", "bob"])
    services.sync_security_team_roster(project, by=None)

    # bob leaves the PMI team.
    _patch_api(monkeypatch, ["alice"])
    assert services.sync_security_team_roster(project, by=None) == 1
    bob = SecurityTeamRosterEntry.objects.get(project=project, eclipse_username="bob")
    assert bob.soft_removed_at is not None

    # bob returns → row reactivates (no duplicate).
    _patch_api(monkeypatch, ["alice", "bob"])
    assert services.sync_security_team_roster(project, by=None) == 2
    bob.refresh_from_db()
    assert bob.soft_removed_at is None
    assert (
        SecurityTeamRosterEntry.objects.filter(project=project, eclipse_username="bob").count() == 1
    )


@pytest.mark.django_db
def test_reuses_existing_user_by_email(monkeypatch, make_user, make_project):
    """A roster member whose email already belongs to a (real) user reuses
    that account — never creates a duplicate, never overrides it to a shadow."""
    real = make_user(email="alice@eclipse.org", groups=["some-group"])
    assert real.is_provisioned is False
    project = make_project("p")
    _patch_api(monkeypatch, ["alice"])

    services.sync_security_team_roster(project, by=None)

    entry = SecurityTeamRosterEntry.objects.get(project=project, eclipse_username="alice")
    assert entry.user_id == real.pk
    real.refresh_from_db()
    # Reused as-is: still a real user, still in its group.
    assert real.is_provisioned is False
    assert real.groups.filter(name="some-group").exists()
    assert User.objects.filter(email__iexact="alice@eclipse.org").count() == 1


@pytest.mark.django_db
def test_email_failure_keeps_existing_row(monkeypatch, make_project):
    project = make_project("p")
    _patch_api(monkeypatch, ["alice"])
    services.sync_security_team_roster(project, by=None)

    # Next run: alice still on PMI, but her email lookup fails transiently.
    def boom(username):
        raise EclipseApiError("profile fetch failed")

    monkeypatch.setattr(services, "fetch_account_email", boom)
    active = services.sync_security_team_roster(project, by=None)
    # Row is NOT soft-removed just because the email blip happened.
    assert active == 1
    entry = SecurityTeamRosterEntry.objects.get(project=project, eclipse_username="alice")
    assert entry.soft_removed_at is None


@pytest.mark.django_db
def test_member_without_email_not_provisioned(monkeypatch, make_project):
    project = make_project("p")
    _patch_api(monkeypatch, ["alice"], emails={"alice": None})
    active = services.sync_security_team_roster(project, by=None)
    assert active == 0
    assert not SecurityTeamRosterEntry.objects.filter(project=project).exists()
    assert not User.objects.filter(is_provisioned=True).exists()


@pytest.mark.django_db
def test_one_account_two_projects_shares_one_user(monkeypatch, make_project):
    p1 = make_project("p1")
    p2 = make_project("p2")
    _patch_api(monkeypatch, ["alice"])
    services.sync_security_team_roster(p1, by=None)
    services.sync_security_team_roster(p2, by=None)

    assert SecurityTeamRosterEntry.objects.filter(eclipse_username="alice").count() == 2
    assert User.objects.filter(email__iexact="alice@eclipse.org").count() == 1


@pytest.mark.django_db
def test_failure_records_error_without_raising(monkeypatch, make_project):
    project = make_project("p")

    def boom(slug):
        raise EclipseApiError("PMI down: token=secret")

    monkeypatch.setattr(services, "fetch_project_members", boom)
    # Does not raise.
    services.sync_security_team_roster(project, by=None)
    project.refresh_from_db()
    assert project.last_roster_sync_error
    assert "secret" not in project.last_roster_sync_error  # redacted


@pytest.mark.django_db
def test_audit_entry_recorded(monkeypatch, make_project):
    project = make_project("p")
    _patch_api(monkeypatch, ["alice"])
    services.sync_security_team_roster(project, by=None)
    assert AccessLogEntry.objects.filter(action=Action.SECURITY_ROSTER_SYNCED).exists()


@pytest.mark.django_db
def test_run_roster_sync_task_skips_when_disabled(settings):
    settings.PMI_ROSTER_SYNC_ENABLED = False
    from projects.tasks import run_roster_sync

    result = run_roster_sync()
    assert "skipped" in result


@pytest.mark.django_db
def test_sync_all_skips_unsorted(monkeypatch, make_project):
    # The 'unsorted' sentinel project already exists (projects migration 0002).
    make_project("real-project")
    _patch_api(monkeypatch, ["alice"])

    services.sync_all_security_team_rosters(by=None)
    # unsorted is skipped; the real project is synced.
    assert not SecurityTeamRosterEntry.objects.filter(project__slug="unsorted").exists()
    assert SecurityTeamRosterEntry.objects.filter(project__slug="real-project").exists()
