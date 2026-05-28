from __future__ import annotations

import shutil

import pytest
from django.urls import reverse

from advisories.models import Advisory
from publication import tasks as pub_tasks
from publication.models import (
    PublicationArtifact,
    PublicationTask,
    PublicationTaskStatus,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git binary not on PATH")


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    outsider = make_user(email="o@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-cccc-ffff-gggg",
        summary="x",
        created_by=member,
    )
    return {
        "admin": admin,
        "member": member,
        "outsider": outsider,
        "project": project,
        "advisory": advisory,
    }


# ---- /publish endpoint ---------------------------------------------------


@pytest.mark.django_db
def test_publish_endpoint_blocked_for_outsider(client, setup):
    client.force_login(setup["outsider"])
    response = client.post(reverse("publication:publish", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_publish_endpoint_blocked_for_non_mature_member(client, setup):
    client.force_login(setup["member"])
    response = client.post(reverse("publication:publish", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_publish_endpoint_creates_task_for_admin(client, setup, monkeypatch):
    # Stub publish_files so the test isn't dependent on Git config
    def _stub(**_):
        from publication.git_service import PublishResult

        return PublishResult(commit_sha="deadbeef" * 5, pushed_to="main")

    monkeypatch.setattr(pub_tasks, "publish_files", _stub)
    client.force_login(setup["admin"])
    response = client.post(reverse("publication:publish", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 302
    assert PublicationTask.objects.filter(advisory=setup["advisory"]).exists()


# ---- Retry endpoint ------------------------------------------------------


@pytest.mark.django_db
def test_retry_endpoint_blocked_for_non_admin(client, setup):
    task = PublicationTask.objects.create(
        advisory=setup["advisory"],
        version=setup["advisory"].versions.get(version=1),
        status=PublicationTaskStatus.FAILED,
        last_error="x",
    )
    client.force_login(setup["outsider"])
    response = client.post(reverse("publication:retry", args=[task.pk]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_retry_endpoint_400_for_non_failed_task(client, setup):
    task = PublicationTask.objects.create(
        advisory=setup["advisory"],
        version=setup["advisory"].versions.get(version=1),
        status=PublicationTaskStatus.SUCCEEDED,
    )
    client.force_login(setup["admin"])
    response = client.post(reverse("publication:retry", args=[task.pk]))
    assert response.status_code == 400


# ---- Artifact preview ----------------------------------------------------


@pytest.mark.django_db
def test_artifact_preview_blocked_for_outsider(client, setup):
    v = setup["advisory"].versions.get(version=1)
    task = PublicationTask.objects.create(advisory=setup["advisory"], version=v)
    PublicationArtifact.objects.create(
        task=task, kind=PublicationArtifact.Kind.OSV, path="osv/x.json", content={"id": "x"}
    )
    client.force_login(setup["outsider"])
    response = client.get(
        reverse("publication:artifact", args=[task.pk, PublicationArtifact.Kind.OSV])
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_artifact_preview_renders_for_member(client, setup):
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
        reverse("publication:artifact", args=[task.pk, PublicationArtifact.Kind.OSV])
    )
    assert response.status_code == 200
    assert b"ECL-cccc-ffff-gggg" in response.content


@pytest.mark.django_db
def test_artifact_download_returns_json(client, setup):
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
        reverse("publication:artifact_download", args=[task.pk, PublicationArtifact.Kind.OSV])
    )
    assert response.status_code == 200
    assert response["Content-Type"] == "application/json"
    assert b"ECL-cccc-ffff-gggg" in response.content
