"""Shadow → real promotion on first OIDC login, and the roster-vs-claim split.

A pre-provisioned shadow user (from the security-team roster sync) holds no
authorization. On first login it is linked by email, ``is_provisioned`` clears,
and authorization comes entirely from the OIDC group claim — never from the
roster. Conversely, removing an already-logged-in member from the roster must
not touch their (claim-driven) access. See INV-OIDC-5.
"""

from __future__ import annotations

import pytest
from django.utils import timezone

from accounts.auth import AdvisoryHubOIDCBackend
from accounts.models import User
from advisories import permissions as perms
from audit.models import Action, AuditLogEntry
from projects.models import SecurityTeamRosterEntry


@pytest.fixture
def backend():
    return AdvisoryHubOIDCBackend()


def _shadow(email: str) -> User:
    return User.objects.create_user(email=email, is_provisioned=True)


@pytest.mark.django_db
def test_first_login_promotes_shadow_and_claim_confers_access(backend, make_project):
    project = make_project("eclipse-jetty")  # security_team group: eclipse-jetty-security
    shadow = _shadow("alice@eclipse.org")
    entry = SecurityTeamRosterEntry.objects.create(
        project=project,
        eclipse_username="alice",
        email="alice@eclipse.org",
        user=shadow,
        last_seen_in_pmi_at=timezone.now(),
    )

    claims = {
        "sub": "alice-sub",
        "email": "alice@eclipse.org",
        "email_verified": True,
        # SPN-form group claim → bare "eclipse-jetty-security" after sync.
        "groups": ["eclipse-jetty-security@accounts.eclipse.org"],
    }
    backend.update_user(shadow, claims)

    shadow.refresh_from_db()
    assert shadow.is_provisioned is False
    assert shadow.oidc_subject == "alice-sub"
    # Access now comes from the claim — they're in the project's security team.
    assert perms.is_security_team_member(shadow, project)
    # Roster row stays linked.
    entry.refresh_from_db()
    assert entry.user_id == shadow.pk
    # The promotion is recorded in the durable ledger.
    assert AuditLogEntry.objects.filter(action=Action.SHADOW_USER_LINKED, actor=shadow).exists()


@pytest.mark.django_db
def test_login_without_team_claim_grants_no_access(backend, make_project):
    """A shadow whose claim omits the team group becomes a real user with no
    access — the roster never confers authorization."""
    project = make_project("eclipse-jetty")
    shadow = _shadow("bob@eclipse.org")
    SecurityTeamRosterEntry.objects.create(
        project=project,
        eclipse_username="bob",
        email="bob@eclipse.org",
        user=shadow,
        last_seen_in_pmi_at=timezone.now(),
    )
    claims = {"sub": "bob-sub", "email": "bob@eclipse.org", "email_verified": True, "groups": []}
    backend.update_user(shadow, claims)

    shadow.refresh_from_db()
    assert shadow.is_provisioned is False
    assert not perms.is_security_team_member(shadow, project)


@pytest.mark.django_db
def test_roster_removal_does_not_deauthorize_logged_in_user(backend, make_project, monkeypatch):
    """Once a member has logged in, dropping them from the PMI roster must not
    revoke their claim-driven access."""
    from projects import services

    project = make_project("eclipse-jetty")
    shadow = _shadow("carol@eclipse.org")
    SecurityTeamRosterEntry.objects.create(
        project=project,
        eclipse_username="carol",
        email="carol@eclipse.org",
        user=shadow,
        last_seen_in_pmi_at=timezone.now(),
    )
    backend.update_user(
        shadow,
        {
            "sub": "carol-sub",
            "email": "carol@eclipse.org",
            "email_verified": True,
            "groups": ["eclipse-jetty-security@accounts.eclipse.org"],
        },
    )
    shadow.refresh_from_db()
    assert perms.is_security_team_member(shadow, project)

    # PMI drops carol from the roster.
    monkeypatch.setattr(services, "fetch_project_members", lambda slug: [])
    monkeypatch.setattr(services, "fetch_account_email", lambda u: None)
    services.sync_security_team_roster(project, by=None)

    shadow.refresh_from_db()
    # Still authorized — access is claim-driven, untouched by roster removal.
    assert perms.is_security_team_member(shadow, project)
    assert shadow.is_active is True
