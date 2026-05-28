from __future__ import annotations

import pytest
from django.urls import reverse

from advisories.models import Advisory, State


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    outsider = make_user(email="o@example.org")
    project_a = make_project("project-a", team_members=[member])
    project_b = make_project("project-b")
    a1 = Advisory.objects.create(project=project_a, summary="visible-marker")
    a2 = Advisory.objects.create(project=project_b, summary="hidden-marker")
    return {
        "admin": admin,
        "member": member,
        "outsider": outsider,
        "project_a": project_a,
        "project_b": project_b,
        "a1": a1,
        "a2": a2,
    }


@pytest.mark.django_db
def test_list_requires_auth(client):
    response = client.get(reverse("api:advisory_list"))
    assert response.status_code == 401
    assert response.json()["error"] == "not_authenticated"


@pytest.mark.django_db
def test_list_returns_only_visible_for_member(client, setup):
    client.force_login(setup["member"])
    response = client.get(reverse("api:advisory_list"))
    assert response.status_code == 200
    payload = response.json()
    ids = [r["advisory_id"] for r in payload["results"]]
    assert setup["a1"].advisory_id in ids
    assert setup["a2"].advisory_id not in ids
    assert payload["total"] == 1


@pytest.mark.django_db
def test_list_does_not_leak_published_advisories_from_other_projects(client, setup):
    """A member of project_a must not see a *published* advisory on project_b."""
    setup["a2"].state = State.PUBLISHED
    setup["a2"].save()
    client.force_login(setup["member"])
    response = client.get(reverse("api:advisory_list"))
    assert response.status_code == 200
    ids = {r["advisory_id"] for r in response.json()["results"]}
    assert setup["a1"].advisory_id in ids
    assert setup["a2"].advisory_id not in ids


@pytest.mark.django_db
def test_list_admin_sees_everything(client, setup):
    client.force_login(setup["admin"])
    response = client.get(reverse("api:advisory_list"))
    ids = {r["advisory_id"] for r in response.json()["results"]}
    assert {setup["a1"].advisory_id, setup["a2"].advisory_id}.issubset(ids)


@pytest.mark.django_db
def test_list_filter_by_project(client, setup):
    client.force_login(setup["admin"])
    response = client.get(reverse("api:advisory_list"), {"project": str(setup["project_a"].id)})
    ids = {r["advisory_id"] for r in response.json()["results"]}
    assert ids == {setup["a1"].advisory_id}


@pytest.mark.django_db
def test_list_filter_by_state(client, setup):
    setup["a2"].state = State.PUBLISHED
    setup["a2"].save()
    client.force_login(setup["admin"])
    response = client.get(reverse("api:advisory_list"), {"state": "published"})
    assert {r["advisory_id"] for r in response.json()["results"]} == {setup["a2"].advisory_id}


@pytest.mark.django_db
def test_list_invalid_state_returns_400(client, setup):
    client.force_login(setup["admin"])
    response = client.get(reverse("api:advisory_list"), {"state": "invented"})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_state"


@pytest.mark.django_db
def test_list_full_text_search(client, setup):
    client.force_login(setup["admin"])
    response = client.get(reverse("api:advisory_list"), {"q": "visible-marker"})
    assert {r["advisory_id"] for r in response.json()["results"]} == {setup["a1"].advisory_id}


@pytest.mark.django_db
def test_list_pagination(client, setup, make_project):
    project = make_project("p3", team_members=[setup["admin"]])
    for i in range(30):
        Advisory.objects.create(project=project, summary=f"bulk-{i}")
    client.force_login(setup["admin"])
    page1 = client.get(reverse("api:advisory_list"), {"page": 1, "page_size": 10}).json()
    assert page1["page"] == 1
    assert len(page1["results"]) == 10
    assert page1["total"] >= 30


@pytest.mark.django_db
def test_detail_403_for_outsider_on_draft(client, setup):
    client.force_login(setup["outsider"])
    response = client.get(reverse("api:advisory_detail", args=[setup["a1"].advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_detail_returns_full_record(client, setup):
    client.force_login(setup["member"])
    response = client.get(reverse("api:advisory_detail", args=[setup["a1"].advisory_id]))
    assert response.status_code == 200
    body = response.json()
    assert body["advisory_id"] == setup["a1"].advisory_id
    assert body["project"]["slug"] == setup["project_a"].slug
    assert body["state"] == "draft"
    assert isinstance(body["aliases"], list)


@pytest.mark.django_db
def test_detail_404_for_unknown_id(client, setup):
    client.force_login(setup["member"])
    response = client.get(reverse("api:advisory_detail", args=["ECL-xxxx-xxxx-xxxx"]))
    assert response.status_code == 404
