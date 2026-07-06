"""Tests for OIDC group sync and user creation."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from django.contrib.auth.models import Group
from django.test import RequestFactory, override_settings
from django.urls import reverse

from accounts.auth import AdvisoryHubOIDCBackend, provider_logout, sync_groups_from_claims
from accounts.models import User


@pytest.mark.django_db
def test_create_user_from_email():
    user = User.objects.create_user(email="alice@example.org")
    assert user.email == "alice@example.org"
    assert not user.has_usable_password()


@pytest.mark.django_db
def test_sync_groups_replaces_membership(settings):
    settings.OIDC_GROUP_CLAIM = "groups"
    user = User.objects.create_user(email="alice@example.org")
    user.groups.add(Group.objects.get_or_create(name="legacy")[0])

    sync_groups_from_claims(
        user,
        {"groups": ["jakartaee-security@localhost", "advisoryhub-security@localhost"]},
    )

    names = set(user.groups.values_list("name", flat=True))
    assert names == {"jakartaee-security", "advisoryhub-security"}
    assert "legacy" not in names


@pytest.mark.django_db
def test_sync_groups_handles_missing_claim(settings):
    settings.OIDC_GROUP_CLAIM = "groups"
    user = User.objects.create_user(email="bob@example.org")
    user.groups.add(Group.objects.get_or_create(name="kept")[0])

    sync_groups_from_claims(user, {"sub": "abc"})  # claim absent

    assert list(user.groups.values_list("name", flat=True)) == []


@pytest.mark.django_db
def test_sync_groups_string_claim_treated_as_single_group(settings):
    settings.OIDC_GROUP_CLAIM = "role"
    user = User.objects.create_user(email="c@example.org")

    sync_groups_from_claims(user, {"role": "advisoryhub-security@localhost"})

    assert list(user.groups.values_list("name", flat=True)) == ["advisoryhub-security"]


@pytest.mark.django_db
def test_sync_groups_strips_spn_suffix(settings):
    """Kanidm emits groups as ``name@domain``; we store only the bare name
    so ``OIDC_ADMIN_GROUP`` (configured as a bare name) matches."""
    settings.OIDC_GROUP_CLAIM = "groups"
    user = User.objects.create_user(email="spn@example.org")

    sync_groups_from_claims(
        user,
        {"groups": ["advisoryhub-security@localhost", "eclipse-jetty-security@localhost"]},
    )

    names = set(user.groups.values_list("name", flat=True))
    assert names == {"advisoryhub-security", "eclipse-jetty-security"}


@pytest.mark.django_db
def test_sync_groups_drops_uuid_duplicates(settings):
    """Kanidm emits each group twice in the claim — once by UUID and once
    by SPN. The UUID copies must not become Django Group rows."""
    settings.OIDC_GROUP_CLAIM = "groups"
    user = User.objects.create_user(email="dup@example.org")

    sync_groups_from_claims(
        user,
        {
            "groups": [
                "65767ecb-6ad3-480f-9b2b-ab9fe51c2378",
                "advisoryhub-security@localhost",
            ]
        },
    )

    names = set(user.groups.values_list("name", flat=True))
    assert names == {"advisoryhub-security"}
    # No Group row was ever created for the UUID-shape claim entry.
    assert not Group.objects.filter(name__startswith="65767ecb").exists()


@pytest.mark.django_db
def test_sync_groups_drops_kanidm_idm_internal_groups(settings):
    """Kanidm leaks its internal IDM groups (idm_all_persons,
    idm_all_accounts, …) into the claim; they're meaningless to
    AdvisoryHub and shouldn't pollute auth_group."""
    settings.OIDC_GROUP_CLAIM = "groups"
    user = User.objects.create_user(email="idm@example.org")

    sync_groups_from_claims(
        user,
        {
            "groups": [
                "idm_all_persons@localhost",
                "idm_all_accounts@localhost",
                "idm_people_self_name_write@localhost",
                "advisoryhub-security@localhost",
            ]
        },
    )

    names = set(user.groups.values_list("name", flat=True))
    assert names == {"advisoryhub-security"}


@pytest.mark.django_db
def test_is_global_admin(settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    user = User.objects.create_user(email="d@example.org")
    assert not user.is_global_admin
    user.groups.add(Group.objects.get_or_create(name="advisoryhub-security")[0])
    assert User.objects.get(pk=user.pk).is_global_admin


# ---------------------------------------------------------------------------
# Admin-flag sync from OIDC group membership
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_apply_claims_grants_admin_flags_when_in_admin_group(settings):
    settings.OIDC_GROUP_CLAIM = "groups"
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    user = User.objects.create_user(email="admin@example.org")
    assert not user.is_staff and not user.is_superuser

    AdvisoryHubOIDCBackend()._apply_claims(
        user, {"sub": "x", "groups": ["advisoryhub-security@localhost"]}
    )

    user.refresh_from_db()
    assert user.is_staff
    assert user.is_superuser


@pytest.mark.django_db
def test_apply_claims_revokes_admin_flags_when_dropped_from_admin_group(settings):
    settings.OIDC_GROUP_CLAIM = "groups"
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    user = User.objects.create_user(email="ex-admin@example.org", is_staff=True, is_superuser=True)

    AdvisoryHubOIDCBackend()._apply_claims(
        user, {"sub": "x", "groups": ["eclipse-jetty-security@localhost"]}
    )

    user.refresh_from_db()
    assert not user.is_staff
    assert not user.is_superuser


@pytest.mark.django_db
def test_apply_claims_does_not_grant_admin_flags_for_non_admin_groups(settings):
    settings.OIDC_GROUP_CLAIM = "groups"
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    user = User.objects.create_user(email="alice@example.org")

    AdvisoryHubOIDCBackend()._apply_claims(
        user, {"sub": "x", "groups": ["eclipse-jetty-security@localhost"]}
    )

    user.refresh_from_db()
    assert not user.is_staff
    assert not user.is_superuser


# ---------------------------------------------------------------------------
# RP-initiated logout
# ---------------------------------------------------------------------------


@override_settings(
    OIDC_OP_LOGOUT_ENDPOINT="https://op.example/end_session",
    LOGOUT_REDIRECT_URL="/accounts/signed-out/",
)
def test_provider_logout_builds_end_session_url_with_id_token_hint():
    request = RequestFactory().post("/oidc/logout/", HTTP_HOST="advisoryhub.example")
    # RequestFactory has no session middleware; provider_logout only needs .get().
    request.session = {"oidc_id_token": "eyJ.fake.token"}  # type: ignore[assignment]

    url = provider_logout(request)

    split = urlsplit(url)
    assert f"{split.scheme}://{split.netloc}{split.path}" == "https://op.example/end_session"
    params = parse_qs(split.query)
    assert params["id_token_hint"] == ["eyJ.fake.token"]
    assert params["post_logout_redirect_uri"] == ["http://advisoryhub.example/accounts/signed-out/"]


@override_settings(
    OIDC_OP_LOGOUT_ENDPOINT="https://op.example/end_session",
    LOGOUT_REDIRECT_URL="/accounts/signed-out/",
)
def test_provider_logout_omits_id_token_hint_when_session_lacks_it():
    request = RequestFactory().post("/oidc/logout/", HTTP_HOST="advisoryhub.example")
    request.session = {}  # type: ignore[assignment]

    url = provider_logout(request)

    params = parse_qs(urlsplit(url).query)
    assert "id_token_hint" not in params
    assert "post_logout_redirect_uri" in params


@override_settings(OIDC_OP_LOGOUT_ENDPOINT="", LOGOUT_REDIRECT_URL="/accounts/signed-out/")
def test_provider_logout_falls_back_to_local_redirect_when_op_endpoint_unset():
    request = RequestFactory().post("/oidc/logout/")
    request.session = {"oidc_id_token": "eyJ.fake.token"}  # type: ignore[assignment]

    assert provider_logout(request) == "/accounts/signed-out/"


@pytest.mark.django_db
def test_signed_out_view_is_anonymous_accessible(client):
    """The post-logout landing must NOT redirect anonymous users back to
    login — otherwise the OP's SSO session would silently re-authenticate
    them and Sign out would appear to be a no-op."""
    response = client.get(reverse("accounts:signed_out"))
    assert response.status_code == 200
    assert b"signed out" in response.content.lower()
