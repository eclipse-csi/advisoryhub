from __future__ import annotations

import pytest
from django.urls import reverse

from advisories.models import Advisory
from publication.models import (
    PublicationArtifact,
    PublicationTask,
    PublicationTaskStatus,
)


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    outsider = make_user(email="o@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(
        project=project, summary="x", created_by=member, advisory_id="ECL-cccc-ffff-gggg"
    )
    return {
        "admin": admin,
        "member": member,
        "outsider": outsider,
        "project": project,
        "advisory": advisory,
    }


@pytest.mark.django_db
def test_publication_status_403_for_outsider(client, setup):
    client.force_login(setup["outsider"])
    response = client.get(reverse("api:publication_status", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_publication_status_returns_tasks(client, setup):
    v = setup["advisory"].versions.get(version=1)
    PublicationTask.objects.create(
        advisory=setup["advisory"],
        version=v,
        status=PublicationTaskStatus.SUCCEEDED,
        commit_sha="cafebabe",
    )
    client.force_login(setup["member"])
    response = client.get(reverse("api:publication_status", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["tasks"]) == 1
    assert payload["tasks"][0]["status"] == "succeeded"


@pytest.mark.django_db
def test_publish_endpoint_blocked_for_outsider(client, setup):
    client.force_login(setup["outsider"])
    response = client.post(reverse("api:publish", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_publish_endpoint_creates_task(client, setup, monkeypatch):
    from publication import tasks as pub_tasks

    monkeypatch.setattr(
        pub_tasks,
        "publish_files",
        lambda **_: __import__("publication.git_service", fromlist=["PublishResult"]).PublishResult(
            commit_sha="x" * 40, pushed_to="main"
        ),
    )
    client.force_login(setup["admin"])
    response = client.post(reverse("api:publish", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 202
    assert PublicationTask.objects.filter(advisory=setup["advisory"]).exists()


@pytest.mark.django_db
def test_publish_endpoint_409_when_in_progress(client, setup):
    v = setup["advisory"].versions.get(version=1)
    PublicationTask.objects.create(
        advisory=setup["advisory"],
        version=v,
        status=PublicationTaskStatus.QUEUED,
    )
    client.force_login(setup["admin"])
    response = client.post(reverse("api:publish", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 409
    assert response.json()["error"] == "in_progress"


@pytest.mark.django_db
def test_retry_endpoint_400_when_not_failed(client, setup):
    v = setup["advisory"].versions.get(version=1)
    task = PublicationTask.objects.create(
        advisory=setup["advisory"],
        version=v,
        status=PublicationTaskStatus.SUCCEEDED,
    )
    client.force_login(setup["admin"])
    response = client.post(reverse("api:publication_retry", args=[task.pk]))
    assert response.status_code == 400


@pytest.mark.django_db
def test_artifact_preview_returns_content(client, setup):
    v = setup["advisory"].versions.get(version=1)
    task = PublicationTask.objects.create(advisory=setup["advisory"], version=v)
    PublicationArtifact.objects.create(
        task=task,
        kind=PublicationArtifact.Kind.OSV,
        path="osv/x.json",
        content={"id": "ECL-cccc-ffff-gggg"},
    )
    client.force_login(setup["member"])
    response = client.get(
        reverse(
            "api:publication_artifact",
            args=[task.pk, PublicationArtifact.Kind.OSV],
        )
    )
    assert response.status_code == 200
    body = response.json()
    assert body["content"]["id"] == "ECL-cccc-ffff-gggg"
    assert body["kind"] == "osv"


@pytest.mark.django_db
def test_artifact_preview_invalid_kind_returns_400(client, setup):
    v = setup["advisory"].versions.get(version=1)
    task = PublicationTask.objects.create(advisory=setup["advisory"], version=v)
    client.force_login(setup["member"])
    response = client.get(reverse("api:publication_artifact", args=[task.pk, "invented"]))
    assert response.status_code == 400
