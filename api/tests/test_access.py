from __future__ import annotations

import json

import pytest
from django.contrib.auth.models import Group
from django.urls import reverse

from access.models import AdvisoryAccessGrant
from access.models import Permission as AccessPermission
from advisories.models import Advisory


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x")
    return {"member": member, "advisory": advisory}


@pytest.mark.django_db
def test_grants_get_requires_grant_perm(client, setup, make_user):
    outsider = make_user(email="o@example.org")
    client.force_login(outsider)
    response = client.get(reverse("api:grants", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_grant_user_creates_record(client, setup, make_user):
    target = make_user(email="grantee@example.org")
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:grants", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"principal": "user", "email": target.email, "permission": "viewer"}),
        content_type="application/json",
    )
    assert response.status_code == 201
    body = response.json()
    assert body["created"] == "grant"
    assert AdvisoryAccessGrant.objects.filter(
        advisory=setup["advisory"], principal_id=target.pk
    ).exists()


@pytest.mark.django_db
def test_grant_for_unknown_email_creates_invitation(client, setup):
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:grants", args=[setup["advisory"].advisory_id]),
        data=json.dumps(
            {"principal": "user", "email": "newcomer@example.org", "permission": "viewer"}
        ),
        content_type="application/json",
    )
    assert response.status_code == 201
    body = response.json()
    assert body["created"] == "invitation"


@pytest.mark.django_db
def test_grant_to_group(client, setup):
    Group.objects.create(name="reviewers")
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:grants", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"principal": "group", "group": "reviewers", "permission": "viewer"}),
        content_type="application/json",
    )
    assert response.status_code == 201
    assert response.json()["grant"]["principal_type"] == "group"


@pytest.mark.django_db
def test_grant_unknown_group_returns_404(client, setup):
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:grants", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"principal": "group", "group": "nope", "permission": "viewer"}),
        content_type="application/json",
    )
    assert response.status_code == 404


@pytest.mark.django_db
def test_invalid_permission_rejected(client, setup, make_user):
    target = make_user(email="t@example.org")
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:grants", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"principal": "user", "email": target.email, "permission": "admin"}),
        content_type="application/json",
    )
    assert response.status_code == 400


@pytest.mark.django_db
def test_grant_owner_rejected_at_api_layer(client, setup, make_user):
    """`owner` is not grantable — the API surface must refuse it with a 400."""
    target = make_user(email="t@example.org")
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:grants", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"principal": "user", "email": target.email, "permission": "owner"}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "not grantable" in response.json()["message"].lower()


@pytest.mark.django_db
def test_revoke_grant(client, setup, make_user):
    target = make_user(email="grantee@example.org")
    from access.services import grant_to_user

    grant = grant_to_user(setup["advisory"], target, AccessPermission.VIEWER, by=setup["member"])
    client.force_login(setup["member"])
    response = client.delete(
        reverse(
            "api:grant_detail",
            args=[setup["advisory"].advisory_id, grant.pk],
        )
    )
    assert response.status_code == 200
    assert not AdvisoryAccessGrant.objects.filter(pk=grant.pk).exists()
