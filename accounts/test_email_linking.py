"""OIDC email-verified gating for account linking (review finding S2).

The stable ``sub`` match is authoritative; the email *fallback* is only
trusted when the OP didn't explicitly mark the address unverified.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import SuspiciousOperation

from access.models import AdvisoryAccessGrant, Permission, PrincipalType
from access.services import invite_email
from accounts.auth import AdvisoryHubOIDCBackend, _email_is_verified
from accounts.models import User
from advisories.models import Advisory


@pytest.fixture
def backend():
    return AdvisoryHubOIDCBackend()


@pytest.fixture
def invited(make_user, make_project):
    """An advisory with a PendingInvitation addressed to a not-yet-registered email."""
    inviter = make_user(email="owner@example.org")
    project = make_project("eclipse-jetty", team_members=[inviter])
    advisory = Advisory.objects.create(project=project, summary="embargoed")
    target = "victim@corp.example"
    invitation = invite_email(advisory, target, Permission.COLLABORATOR, by=inviter)
    assert not User.objects.filter(email__iexact=target).exists()
    return advisory, target, invitation


def test_verified_defaults_true_when_absent():
    assert _email_is_verified({"email": "a@b.org"}) is True


def test_verified_blocks_explicit_bool_false():
    assert _email_is_verified({"email_verified": False}) is False


def test_verified_blocks_string_false():
    assert _email_is_verified({"email_verified": "false"}) is False


def test_verified_allows_string_true():
    assert _email_is_verified({"email_verified": "true"}) is True


@pytest.mark.django_db
def test_email_fallback_links_when_verified(backend, make_user):
    user = make_user(email="link@example.org")
    claims = {"sub": "brand-new-sub", "email": "link@example.org", "email_verified": True}
    assert list(backend.filter_users_by_claims(claims)) == [user]


@pytest.mark.django_db
def test_email_fallback_refused_when_unverified(backend, make_user):
    make_user(email="link@example.org")
    claims = {"sub": "brand-new-sub", "email": "link@example.org", "email_verified": False}
    assert list(backend.filter_users_by_claims(claims)) == []


@pytest.mark.django_db
def test_sub_match_ignores_email_gate(backend, make_user):
    user = make_user(email="link@example.org")
    user.oidc_subject = "stable-sub"
    user.save(update_fields=["oidc_subject"])
    # A matching sub is authoritative even with an unverified email claim.
    claims = {"sub": "stable-sub", "email": "spoof@example.org", "email_verified": False}
    assert list(backend.filter_users_by_claims(claims)) == [user]


def test_verified_blocks_explicit_null():
    # An explicit null is "the OP could not vouch for this address" → not verified.
    assert _email_is_verified({"email_verified": None}) is False


# --- create_user gate (INV-OIDC-6) -----------------------------------------
#
# The email fallback in filter_users_by_claims was already gated (review finding
# S2). The *create* path was not: an unverified email created an account, redeemed
# any PendingInvitation addressed to it, and squatted the unique address.


@pytest.mark.django_db
def test_create_user_refused_when_email_explicitly_unverified(backend, invited):
    advisory, target, invitation = invited
    claims = {"sub": "attacker-sub", "email": target, "email_verified": False, "name": "Mallory"}

    with pytest.raises(SuspiciousOperation):
        backend.create_user(claims)

    # No account created, address not squatted, invitation untouched, no grant.
    assert not User.objects.filter(email__iexact=target).exists()
    invitation.refresh_from_db()
    assert invitation.redeemed_at is None
    assert not AdvisoryAccessGrant.objects.filter(advisory=advisory).exists()


@pytest.mark.django_db
def test_create_user_redeems_when_email_verified(backend, invited):
    advisory, target, invitation = invited
    claims = {"sub": "victim-sub", "email": target, "email_verified": True}

    user = backend.create_user(claims)

    assert user.email == target
    invitation.refresh_from_db()
    assert invitation.redeemed_at is not None
    assert invitation.redeemed_by_id == user.pk
    grant = AdvisoryAccessGrant.objects.get(
        advisory=advisory, principal_type=PrincipalType.USER, principal_id=user.pk
    )
    assert grant.permission == Permission.COLLABORATOR


@pytest.mark.django_db
def test_create_user_redeems_when_verified_claim_absent(backend, invited):
    """Kanidm omits email_verified; with the default (require off) it stays trusted."""
    advisory, target, invitation = invited
    claims = {"sub": "victim-sub", "email": target}  # no email_verified key

    user = backend.create_user(claims)

    invitation.refresh_from_db()
    assert invitation.redeemed_at is not None
    assert AdvisoryAccessGrant.objects.filter(
        advisory=advisory, principal_type=PrincipalType.USER, principal_id=user.pk
    ).exists()


# --- strict mode: OIDC_REQUIRE_EMAIL_VERIFIED also rejects the *absent* case ---


def test_verified_absent_rejected_in_strict_mode(settings):
    settings.OIDC_REQUIRE_EMAIL_VERIFIED = True
    assert _email_is_verified({"email": "a@b.org"}) is False


def test_verified_absent_trusted_by_default(settings):
    settings.OIDC_REQUIRE_EMAIL_VERIFIED = False
    assert _email_is_verified({"email": "a@b.org"}) is True


@pytest.mark.django_db
def test_create_user_refused_when_absent_and_strict(backend, invited, settings):
    settings.OIDC_REQUIRE_EMAIL_VERIFIED = True
    advisory, target, invitation = invited
    claims = {"sub": "attacker-sub", "email": target}  # absent email_verified

    with pytest.raises(SuspiciousOperation):
        backend.create_user(claims)

    assert not User.objects.filter(email__iexact=target).exists()
    invitation.refresh_from_db()
    assert invitation.redeemed_at is None


@pytest.mark.django_db
def test_email_fallback_refused_when_absent_and_strict(backend, make_user, settings):
    settings.OIDC_REQUIRE_EMAIL_VERIFIED = True
    make_user(email="link@example.org")
    claims = {"sub": "brand-new-sub", "email": "link@example.org"}  # absent
    assert list(backend.filter_users_by_claims(claims)) == []
