"""Top-level pytest configuration shared across apps."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clear_cache():
    """Reset the default cache around every test.

    The DB is rolled back per test, but the cache is not — and the
    maintenance-mode snapshot (and rate-limit counters) live there. Clearing
    keeps a test that enables maintenance from leaking an "on" snapshot into
    the next test, and gives rate-limit tests fresh counters.
    """
    from django.core.cache import cache

    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def admin_group(db, settings):
    from django.contrib.auth.models import Group

    return Group.objects.get_or_create(name=settings.OIDC_ADMIN_GROUP)[0]


@pytest.fixture
def make_user(db):
    from accounts.models import User

    counter = {"n": 0}

    def _make(email: str | None = None, groups: list[str] | None = None, **kwargs):
        from django.contrib.auth.models import Group

        counter["n"] += 1
        email = email or f"user{counter['n']}@example.org"
        user = User.objects.create_user(email=email, **kwargs)
        for name in groups or []:
            group, _ = Group.objects.get_or_create(name=name)
            user.groups.add(group)
        return user

    return _make


@pytest.fixture
def make_project(db):
    from django.contrib.auth.models import Group

    from projects.models import Project

    counter = {"n": 0}

    def _make(
        name: str | None = None,
        team_members: list = None,
        is_mature_publisher: bool = False,
    ) -> Project:
        counter["n"] += 1
        name = name or f"project-{counter['n']}"
        team, _ = Group.objects.get_or_create(name=f"{name}-security")
        project = Project.objects.create(
            slug=name,
            name=name.replace("-", " ").title(),
            security_team=team,
            is_mature_publisher=is_mature_publisher,
        )
        for user in team_members or []:
            user.groups.add(team)
        return project

    return _make
