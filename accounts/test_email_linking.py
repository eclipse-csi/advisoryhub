"""OIDC email-verified gating for account linking (review finding S2).

The stable ``sub`` match is authoritative; the email *fallback* is only
trusted when the OP didn't explicitly mark the address unverified.
"""

from __future__ import annotations

import pytest

from accounts.auth import AdvisoryHubOIDCBackend, _email_is_verified


@pytest.fixture
def backend():
    return AdvisoryHubOIDCBackend()


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
