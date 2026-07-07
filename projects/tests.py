from __future__ import annotations

import pytest


@pytest.mark.django_db
def test_security_team_membership(make_user, make_project):
    alice = make_user(email="alice@example.org")
    project = make_project("eclipse-jetty", team_members=[alice])
    bob = make_user(email="bob@example.org")

    assert project.is_security_team_member(alice)
    assert not project.is_security_team_member(bob)


@pytest.mark.django_db
def test_anonymous_is_not_team_member(make_project):
    from django.contrib.auth.models import AnonymousUser

    project = make_project("eclipse-jetty")
    assert not project.is_security_team_member(AnonymousUser())


# ---- Audited project CRUD services (INV-AUDIT-3) ---------------------------


@pytest.mark.django_db
def test_create_project_service_creates_group_and_audits(make_user):
    from django.contrib.auth.models import Group

    from audit.models import Action, AuditLogEntry
    from projects import services

    admin = make_user(email="admin@example.org")
    project = services.create_project(
        slug="eclipse-svc",
        name="Eclipse Svc",
        security_team_group_name="eclipse-svc-security",
        by=admin,
    )
    assert Group.objects.filter(name="eclipse-svc-security").exists()
    assert project.security_team.name == "eclipse-svc-security"
    entry = AuditLogEntry.objects.get(action=Action.PROJECT_CREATED)
    assert entry.actor == admin
    assert entry.new_value is not None
    assert entry.new_value["slug"] == "eclipse-svc"
    assert entry.metadata["security_team_group_created"] is True


@pytest.mark.django_db
def test_create_project_service_reuses_existing_group(make_user):
    from django.contrib.auth.models import Group

    from audit.models import Action, AuditLogEntry
    from projects import services

    existing = Group.objects.create(name="shared-secteam")
    project = services.create_project(
        slug="eclipse-shared",
        name="Eclipse Shared",
        security_team_group_name="shared-secteam",
        by=make_user(email="admin@example.org"),
    )
    assert project.security_team_id == existing.pk
    entry = AuditLogEntry.objects.get(action=Action.PROJECT_CREATED)
    assert entry.metadata["security_team_group_created"] is False


@pytest.mark.django_db
def test_update_project_service_records_old_to_new_group(make_user, make_project):
    from audit.models import Action, AuditLogEntry
    from projects import services

    admin = make_user(email="admin@example.org")
    project = make_project("eclipse-move")
    old_group = project.security_team.name
    services.update_project(
        project,
        slug=project.slug,
        name=project.name,
        description=project.description,
        homepage_url=project.homepage_url,
        is_mature_publisher=project.is_mature_publisher,
        security_team_group_name="moved-secteam",
        by=admin,
    )
    project.refresh_from_db()
    assert project.security_team.name == "moved-secteam"
    entry = AuditLogEntry.objects.get(action=Action.PROJECT_UPDATED)
    assert entry.previous_value is not None
    assert entry.new_value is not None
    assert entry.previous_value["security_team"] == old_group
    assert entry.new_value["security_team"] == "moved-secteam"
    assert entry.metadata["changed"] == ["security_team"]


@pytest.mark.django_db
def test_update_project_unchanged_fields_changed_list_empty(make_user, make_project):
    # A no-change save still leaves a ledger row (every successful admin
    # mutation is recorded) — the empty `changed` list documents the no-op.
    from audit.models import Action, AuditLogEntry
    from projects import services

    project = make_project("eclipse-idem")
    services.update_project(
        project,
        slug=project.slug,
        name=project.name,
        description=project.description,
        homepage_url=project.homepage_url,
        is_mature_publisher=project.is_mature_publisher,
        security_team_group_name=project.security_team.name,
        by=make_user(email="admin@example.org"),
    )
    entry = AuditLogEntry.objects.get(action=Action.PROJECT_UPDATED)
    assert entry.metadata["changed"] == []
