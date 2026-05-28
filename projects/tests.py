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
