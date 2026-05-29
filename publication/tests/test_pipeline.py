"""Integration tests for the publication pipeline.

These exercise the full path: ``services.publish`` → version pinning →
``run_publication`` task → OSV/CSAF generation → Git push → advisory
state flip. Failure paths are tested by monkeypatching the Git service to
raise.

The ``CELERY_TASK_ALWAYS_EAGER=True`` test setting makes ``.delay()``
calls run synchronously; we still trigger ``run_publication`` directly in
some tests to bypass ``transaction.on_commit`` semantics.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

git_module = pytest.importorskip("git")
from git import Repo  # noqa: E402

from advisories.models import Advisory, State
from audit.models import Action, AuditLogEntry
from publication import services as pub_services
from publication import tasks as pub_tasks
from publication.git_service import GitPublicationError
from publication.models import (
    PublicationArtifact,
    PublicationTask,
    PublicationTaskStatus,
)


def _git_available() -> bool:
    return shutil.which("git") is not None


pytestmark = pytest.mark.skipif(not _git_available(), reason="git binary not on PATH")


@pytest.fixture
def setup(make_user, make_project, settings, tmp_path):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    outsider = make_user(email="o@example.org")
    project = make_project("p", team_members=[member])

    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-cccc-ffff-gggg",
        summary="Example",
        details="Some details.",
        aliases=["CVE-2026-1234"],
        cwe_ids=["CWE-79"],
        references=[{"type": "ADVISORY", "url": "https://example.org/x"}],
        affected=[
            {
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.5"}],
                    }
                ],
            }
        ],
        created_by=member,
    )

    bare = tmp_path / "remote.git"
    bare.mkdir()
    subprocess.run(
        ["git", "init", "--bare", "--initial-branch=main", str(bare)],
        check=True,
        capture_output=True,
    )
    seed = tmp_path / "seed"
    seed.mkdir()
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(seed)], check=True, capture_output=True
    )
    subprocess.run(["git", "-C", str(seed), "config", "user.email", "seed@example.org"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.name", "Seed"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "commit.gpgsign", "false"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "tag.gpgsign", "false"], check=True)
    (seed / "README.md").write_text("hi\n")
    subprocess.run(["git", "-C", str(seed), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(seed), "commit", "-m", "init"], check=True, capture_output=True
    )
    subprocess.run(["git", "-C", str(seed), "remote", "add", "origin", str(bare)], check=True)
    subprocess.run(
        ["git", "-C", str(seed), "push", "origin", "main"], check=True, capture_output=True
    )

    settings.PUB_REPO_URL = str(bare)
    settings.PUB_REPO_BRANCH = "main"
    settings.PUB_REPO_AUTH = "none"
    settings.PUB_REPO_SSH_KEY_PATH = ""
    settings.PUB_REPO_TOKEN = ""
    settings.PUB_COMMIT_AUTHOR_NAME = "AdvisoryHub Test"
    settings.PUB_COMMIT_AUTHOR_EMAIL = "bot@example.org"
    settings.PUB_OSV_PATH_TEMPLATE = "osv/{advisory_id}.json"
    settings.PUB_CSAF_PATH_TEMPLATE = "csaf/{advisory_id}.json"
    settings.PUB_CVE_PATH_TEMPLATE = "cves/{year}/{bucket}/{cve_id}.json"
    settings.PUB_CVE_ASSIGNER_ORG_ID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
    settings.PUB_CVE_ASSIGNER_SHORT_NAME = "eclipse"

    return {
        "admin": admin,
        "member": member,
        "outsider": outsider,
        "project": project,
        "advisory": advisory,
        "bare_repo": bare,
        "tmp_path": tmp_path,
    }


# ---- Permission ----------------------------------------------------------


@pytest.mark.django_db
def test_publish_blocked_for_outsider(setup):
    from django.core.exceptions import PermissionDenied

    with pytest.raises(PermissionDenied):
        pub_services.publish(setup["advisory"], by=setup["outsider"])


@pytest.mark.django_db
def test_publish_blocked_for_member_when_not_mature_or_approved(setup):
    from django.core.exceptions import PermissionDenied

    with pytest.raises(PermissionDenied):
        pub_services.publish(setup["advisory"], by=setup["member"])


@pytest.mark.django_db
def test_publish_allowed_for_mature_publisher_member(setup):
    setup["project"].is_mature_publisher = True
    setup["project"].save()
    task = pub_services.publish(setup["advisory"], by=setup["member"])
    assert task.status in (PublicationTaskStatus.QUEUED, PublicationTaskStatus.SUCCEEDED)


# ---- Concurrency --------------------------------------------------------


@pytest.mark.django_db
def test_publish_blocked_when_another_run_is_in_flight(setup):
    """A second publish() while the first is still queued/running must error."""
    pub_services.publish(setup["advisory"], by=setup["admin"])
    with pytest.raises(pub_services.PublicationInProgress):
        pub_services.publish(setup["advisory"], by=setup["admin"])
    assert PublicationTask.objects.filter(advisory=setup["advisory"]).count() == 1


@pytest.mark.django_db
def test_publish_view_surfaces_in_flight_message(client, setup):
    from django.urls import reverse

    pub_services.publish(setup["advisory"], by=setup["admin"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("publication:publish", args=[setup["advisory"].advisory_id]),
        follow=True,
    )
    assert response.status_code == 200
    assert any("already in progress" in str(m) for m in response.context["messages"])
    assert PublicationTask.objects.filter(advisory=setup["advisory"]).count() == 1


@pytest.mark.django_db
def test_publish_after_previous_succeeds_creates_new_task(setup, monkeypatch):
    """The in-flight guard releases once the previous task is in a terminal state."""
    from publication import tasks as pub_tasks

    def _stub(**_):
        from publication.git_service import PublishResult

        return PublishResult(commit_sha="cafebabe" * 5, pushed_to="main")

    monkeypatch.setattr(pub_tasks, "publish_files", _stub)

    t1 = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(t1.pk)
    t1.refresh_from_db()
    assert t1.status == PublicationTaskStatus.SUCCEEDED

    setup["advisory"].refresh_from_db()
    setup["advisory"].republish_required = True
    setup["advisory"].save(update_fields=["republish_required"])

    t2 = pub_services.publish(setup["advisory"], by=setup["admin"])
    assert t2.pk != t1.pk


# ---- Success path --------------------------------------------------------


@pytest.mark.django_db
def test_run_publication_writes_files_and_flips_state(setup):
    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)

    task.refresh_from_db()
    setup["advisory"].refresh_from_db()
    assert task.status == PublicationTaskStatus.SUCCEEDED
    assert task.commit_sha
    assert setup["advisory"].state == State.PUBLISHED
    assert setup["advisory"].published_at is not None

    # Verify file content reached the bare repo
    verify = setup["tmp_path"] / "verify"
    Repo.clone_from(str(setup["bare_repo"]), str(verify), branch="main")
    osv_file = verify / "osv" / "ECL-cccc-ffff-gggg.json"
    csaf_file = verify / "csaf" / "ECL-cccc-ffff-gggg.json"
    assert osv_file.exists()
    assert csaf_file.exists()
    assert "ECL-cccc-ffff-gggg" in osv_file.read_text()
    assert "csaf_security_advisory" in csaf_file.read_text()

    # PublicationArtifact rows carry the rendered OSV + CSAF.
    from publication.models import PublicationArtifact

    arts = {a.kind: a.content for a in PublicationArtifact.objects.filter(task=task)}
    assert arts[PublicationArtifact.Kind.OSV]["id"] == "ECL-cccc-ffff-gggg"
    assert arts[PublicationArtifact.Kind.CSAF]["document"]["csaf_version"] == "2.0"

    # Audit entries
    expected = {
        Action.PUBLICATION_EXPORT_STARTED,
        Action.PUBLICATION_OSV_GENERATED,
        Action.PUBLICATION_CSAF_GENERATED,
        Action.PUBLICATION_GIT_COMMIT,
        Action.PUBLICATION_GIT_PUSH,
        Action.ADVISORY_PUBLISHED,
        Action.PUBLICATION_EXPORT_COMPLETED,
    }
    actual = set(
        AuditLogEntry.objects.filter(advisory=setup["advisory"]).values_list("action", flat=True)
    )
    assert expected.issubset(actual)


@pytest.mark.django_db
def test_advisory_state_does_not_flip_until_after_push(setup, monkeypatch):
    """If push fails, advisory must stay in 'draft'."""

    def boom(**_kwargs):
        raise GitPublicationError("simulated push failure")

    monkeypatch.setattr(pub_tasks, "publish_files", boom)
    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)

    task.refresh_from_db()
    setup["advisory"].refresh_from_db()
    assert task.status == PublicationTaskStatus.FAILED
    assert "simulated push failure" in task.last_error
    assert setup["advisory"].state == State.DRAFT
    assert setup["advisory"].published_at is None


@pytest.mark.django_db
def test_secret_redacted_from_last_error(setup, monkeypatch):

    def boom(**_kwargs):
        raise GitPublicationError(
            "fatal: could not auth https://oauth2:ghp_TOPSECRET@github.com/r.git"
        )

    monkeypatch.setattr(pub_tasks, "publish_files", boom)
    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    task.refresh_from_db()
    assert "ghp_TOPSECRET" not in task.last_error
    assert "***" in task.last_error


@pytest.mark.django_db
def test_validation_failure_keeps_state_and_records_failed(setup, monkeypatch):
    """Forcing validate_osv to raise should fail the task before any push."""
    from publication import osv as osv_mod

    monkeypatch.setattr(
        osv_mod,
        "validate_osv",
        lambda doc: (_ for _ in ()).throw(osv_mod.OsvValidationError("missing required field")),
    )
    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    task.refresh_from_db()
    setup["advisory"].refresh_from_db()
    assert task.status == PublicationTaskStatus.FAILED
    assert "missing required field" in task.last_error
    assert setup["advisory"].state == State.DRAFT


# ---- Retry --------------------------------------------------------------


@pytest.mark.django_db
def test_retry_creates_new_task_and_succeeds_after_fix(setup, monkeypatch):
    """First task fails (push raises), second task with monkeypatch removed succeeds."""
    boom = {"raise": True}

    real = pub_tasks.publish_files

    def maybe_boom(**kwargs):
        if boom["raise"]:
            raise GitPublicationError("transient failure")
        return real(**kwargs)

    monkeypatch.setattr(pub_tasks, "publish_files", maybe_boom)

    t1 = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(t1.pk)
    t1.refresh_from_db()
    assert t1.status == PublicationTaskStatus.FAILED

    boom["raise"] = False
    t2 = pub_services.retry(t1, by=setup["admin"])
    pub_tasks.run_publication(t2.pk)
    t2.refresh_from_db()
    setup["advisory"].refresh_from_db()
    assert t2.status == PublicationTaskStatus.SUCCEEDED
    # retry creates a new PublicationTask; both pin the same AdvisoryVersion
    # because no edit happened between t1 and t2. (An edit between the two
    # would have created a new version, which t2 would pin instead.)
    assert t2.pk != t1.pk
    assert t2.version_id == t1.version_id
    assert setup["advisory"].state == State.PUBLISHED


@pytest.mark.django_db
def test_retry_only_for_failed_tasks(setup):
    from django.core.exceptions import PermissionDenied

    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    task.refresh_from_db()
    assert task.status == PublicationTaskStatus.SUCCEEDED
    with pytest.raises(PermissionDenied):
        pub_services.retry(task, by=setup["admin"])


# ---- Edit-after-publish -------------------------------------------------


@pytest.mark.django_db
def test_edit_after_publish_marks_republish_required_and_new_commit_on_republish(setup, client):
    from django.urls import reverse

    # Initial publish
    t1 = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(t1.pk)
    t1.refresh_from_db()
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].state == State.PUBLISHED
    first_commit = t1.commit_sha

    # Edit the published advisory via the UI
    client.force_login(setup["admin"])
    edit_data = {
        "project": setup["project"].pk,
        "summary": "Updated after publication",
        "details": "Now with new info.",
    }
    for prefix in ("aliases", "cwe_ids", "references", "severity", "credits", "affected"):
        edit_data[f"{prefix}-TOTAL_FORMS"] = "0"
        edit_data[f"{prefix}-INITIAL_FORMS"] = "0"
        edit_data[f"{prefix}-MIN_NUM_FORMS"] = "0"
        edit_data[f"{prefix}-MAX_NUM_FORMS"] = "1000"
    # One alias and one reference.
    edit_data.update(
        {
            "aliases-TOTAL_FORMS": "1",
            "aliases-0-value": "CVE-2026-1234",
            "references-TOTAL_FORMS": "1",
            "references-0-type": "ADVISORY",
            "references-0-url": "https://example.org/x",
        }
    )
    client.post(
        reverse("advisories:edit", args=[setup["advisory"].advisory_id]),
        data=edit_data,
    )
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].republish_required is True

    # Re-publish creates a new task and new commit
    t2 = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(t2.pk)
    t2.refresh_from_db()
    setup["advisory"].refresh_from_db()
    assert t2.status == PublicationTaskStatus.SUCCEEDED
    assert t2.commit_sha != first_commit
    assert setup["advisory"].republish_required is False
    assert setup["advisory"].state == State.PUBLISHED


# ---- Artifacts persisted -----------------------------------------------


@pytest.mark.django_db
def test_artifacts_persisted_on_success(setup):
    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    artifacts = {a.kind: a for a in PublicationArtifact.objects.filter(task=task)}
    assert PublicationArtifact.Kind.OSV in artifacts
    assert PublicationArtifact.Kind.CSAF in artifacts
    assert artifacts[PublicationArtifact.Kind.OSV].path == "osv/ECL-cccc-ffff-gggg.json"


# ---- CVE export ----------------------------------------------------------


def _cve_advisory(setup, *, advisory_id, cve_id):
    return Advisory.objects.create(
        project=setup["project"],
        advisory_id=advisory_id,
        summary="Advisory with an assigned CVE",
        details="Some details.",
        assigned_cve_id=cve_id,
        cwe_ids=["CWE-79"],
        references=[{"type": "ADVISORY", "url": "https://example.org/x"}],
        affected=[
            {
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.5"}],
                    }
                ],
            }
        ],
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
        created_by=setup["member"],
    )


@pytest.mark.django_db
def test_run_publication_generates_and_pushes_cve_when_assigned(setup):
    advisory = _cve_advisory(setup, advisory_id="ECL-1111-2222-3333", cve_id="CVE-2026-0001")
    task = pub_services.publish(advisory, by=setup["admin"])
    pub_tasks.run_publication(task.pk)

    task.refresh_from_db()
    advisory.refresh_from_db()
    assert task.status == PublicationTaskStatus.SUCCEEDED
    assert advisory.state == State.PUBLISHED

    arts = {a.kind: a for a in PublicationArtifact.objects.filter(task=task)}
    assert PublicationArtifact.Kind.CVE in arts
    cve_art = arts[PublicationArtifact.Kind.CVE]
    # Year-bucketed cvelistV5 layout.
    assert cve_art.path == "cves/2026/0xxx/CVE-2026-0001.json"
    assert cve_art.content["cveMetadata"]["cveId"] == "CVE-2026-0001"
    assert cve_art.content["dataVersion"] == "5.2.0"

    # File reached the bare repo at the bucketed path.
    verify = setup["tmp_path"] / "verify-cve"
    Repo.clone_from(str(setup["bare_repo"]), str(verify), branch="main")
    assert (verify / "cves" / "2026" / "0xxx" / "CVE-2026-0001.json").exists()

    assert AuditLogEntry.objects.filter(
        advisory=advisory, action=Action.PUBLICATION_CVE_GENERATED
    ).exists()


@pytest.mark.django_db
def test_run_publication_skips_cve_when_unassigned(setup):
    """The fixture advisory has no assigned CVE — only OSV/CSAF are produced."""
    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    task.refresh_from_db()

    kinds = set(PublicationArtifact.objects.filter(task=task).values_list("kind", flat=True))
    assert kinds == {PublicationArtifact.Kind.OSV, PublicationArtifact.Kind.CSAF}
    assert not AuditLogEntry.objects.filter(
        advisory=setup["advisory"], action=Action.PUBLICATION_CVE_GENERATED
    ).exists()


@pytest.mark.django_db
def test_cve_assigner_not_configured_fails_publish(setup, settings):
    """A CVE-assigned advisory cannot publish while the CNA org id is unset."""
    settings.PUB_CVE_ASSIGNER_ORG_ID = ""
    advisory = _cve_advisory(setup, advisory_id="ECL-4444-5555-6666", cve_id="CVE-2026-0009")
    task = pub_services.publish(advisory, by=setup["admin"])
    pub_tasks.run_publication(task.pk)

    task.refresh_from_db()
    advisory.refresh_from_db()
    assert task.status == PublicationTaskStatus.FAILED
    assert "PUB_CVE_ASSIGNER_ORG_ID" in task.last_error
    # State must not flip when any export step fails (INV-LIFECYCLE-3).
    assert advisory.state == State.DRAFT
    assert not PublicationArtifact.objects.filter(task=task).exists()


@pytest.mark.django_db
def test_artifacts_persisted_on_validation_failure(setup, monkeypatch):
    """If only OSV validation fails, the OSV artifact should NOT be persisted
    (we fail fast before storing it)."""
    from publication import osv as osv_mod

    monkeypatch.setattr(
        osv_mod,
        "validate_osv",
        lambda doc: (_ for _ in ()).throw(osv_mod.OsvValidationError("bad")),
    )
    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    assert not PublicationArtifact.objects.filter(task=task).exists()
