from __future__ import annotations

import json

import pytest
from django.urls import reverse

from access.models import Permission as AccessPermission
from access.services import grant_to_user
from advisories.models import Advisory


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x")
    return {"member": member, "project": project, "advisory": advisory}


@pytest.mark.django_db
def test_comments_get_requires_view_access(client, setup, make_user):
    outsider = make_user(email="o@example.org")
    client.force_login(outsider)
    response = client.get(reverse("api:comments", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_comments_post_rejects_outsider(client, setup, make_user):
    """Users without any grant cannot post — but a viewer grant is sufficient."""
    outsider = make_user(email="o@example.org")
    client.force_login(outsider)
    response = client.post(
        reverse("api:comments", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"body": "should fail"}),
        content_type="application/json",
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_comments_post_allowed_for_viewer(client, setup, make_user):
    """The old `comment` level folded into `viewer` — viewer can post comments."""
    user = make_user(email="r@example.org")
    grant_to_user(setup["advisory"], user, AccessPermission.VIEWER, by=setup["member"])
    client.force_login(user)
    response = client.post(
        reverse("api:comments", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"body": "viewer comment"}),
        content_type="application/json",
    )
    assert response.status_code == 201


@pytest.mark.django_db
def test_comments_post_creates_comment(client, setup):
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:comments", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"body": "hello *world*"}),
        content_type="application/json",
    )
    assert response.status_code == 201
    body = response.json()
    assert body["body"] == "hello *world*"
    assert body["author"] == "m@example.org"


@pytest.mark.django_db
def test_comments_get_masks_author_email_for_non_owner(client, setup, make_user):
    """INV-PRIVACY-4: the JSON ``author`` is the raw email for an owner, but a
    masked email for a viewer grantee."""
    from comments import services as cs

    cs.add_comment(setup["advisory"], author=setup["member"], body="hello")
    viewer = make_user(email="v@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["member"])
    url = reverse("api:comments", args=[setup["advisory"].advisory_id])

    client.force_login(setup["member"])
    assert client.get(url).json()["results"][0]["author"] == "m@example.org"

    client.force_login(viewer)
    assert client.get(url).json()["results"][0]["author"] == "m•••@example.org"


@pytest.mark.django_db
def test_comments_post_form_encoded_works_too(client, setup):
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:comments", args=[setup["advisory"].advisory_id]),
        data={"body": "form-encoded"},
    )
    assert response.status_code == 201


@pytest.mark.django_db
def test_comments_post_rejects_empty_body(client, setup):
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:comments", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"body": "   "}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_body"


@pytest.mark.django_db
def test_comments_get_returns_thread(client, setup):
    from comments import services as cs

    cs.add_comment(setup["advisory"], author=setup["member"], body="first")
    cs.add_comment(setup["advisory"], author=setup["member"], body="second")
    client.force_login(setup["member"])
    response = client.get(reverse("api:comments", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 200
    bodies = [c["body"] for c in response.json()["results"]]
    assert bodies == ["first", "second"]


# ---- Internal comments ----------------------------------------------------


@pytest.mark.django_db
def test_api_get_filters_internal_for_viewer(client, setup, make_user):
    from comments import services as cs

    viewer = make_user(email="v@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["member"])
    cs.add_comment(setup["advisory"], author=setup["member"], body="public")
    cs.add_comment(setup["advisory"], author=setup["member"], body="secret", internal=True)

    client.force_login(viewer)
    response = client.get(reverse("api:comments", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 200
    results = response.json()["results"]
    assert {c["body"] for c in results} == {"public"}


@pytest.mark.django_db
def test_api_get_includes_internal_for_collaborator(client, setup, make_user):
    from comments import services as cs

    collab = make_user(email="c@example.org")
    grant_to_user(setup["advisory"], collab, AccessPermission.COLLABORATOR, by=setup["member"])
    cs.add_comment(setup["advisory"], author=setup["member"], body="public")
    cs.add_comment(setup["advisory"], author=setup["member"], body="secret", internal=True)

    client.force_login(collab)
    response = client.get(reverse("api:comments", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 200
    results = response.json()["results"]
    assert {c["body"] for c in results} == {"public", "secret"}
    # Serializer surfaces the flag.
    secret = next(c for c in results if c["body"] == "secret")
    assert secret["is_internal"] is True


@pytest.mark.django_db
def test_api_post_with_is_internal_as_viewer_is_403(client, setup, make_user):
    """A viewer crafting an ``is_internal: true`` POST must be rejected
    by the service layer (the trust boundary), not just by the UI.
    """
    viewer = make_user(email="v@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["member"])
    client.force_login(viewer)
    response = client.post(
        reverse("api:comments", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"body": "trying", "is_internal": True}),
        content_type="application/json",
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_api_post_with_is_internal_as_collaborator_persists_flag(client, setup, make_user):
    collab = make_user(email="c@example.org")
    grant_to_user(setup["advisory"], collab, AccessPermission.COLLABORATOR, by=setup["member"])
    client.force_login(collab)
    response = client.post(
        reverse("api:comments", args=[setup["advisory"].advisory_id]),
        data=json.dumps({"body": "internal", "is_internal": True}),
        content_type="application/json",
    )
    assert response.status_code == 201
    body = response.json()
    assert body["is_internal"] is True
