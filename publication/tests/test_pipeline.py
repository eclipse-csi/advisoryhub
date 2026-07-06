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

from advisories.models import Advisory, ReviewStatus, State
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


def _clone(url: str, dest: str, branch: str = "main") -> None:
    subprocess.run(
        ["git", "clone", "--branch", branch, "--", url, dest],
        check=True,
        capture_output=True,
    )


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
    settings.PUB_OSV_PATH_TEMPLATE = "osv/{year}/{advisory_id}.json"
    settings.PUB_CSAF_PATH_TEMPLATE = "csaf/{year}/{advisory_id}.json"
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


@pytest.mark.django_db
def test_system_publish_skips_can_publish(setup):
    """system=True bypasses the human can_publish gate (by=None) — used by
    auto-publish. A non-mature, unapproved advisory would otherwise be denied."""
    task = pub_services.publish(setup["advisory"], by=None, system=True)
    assert task.status in (PublicationTaskStatus.QUEUED, PublicationTaskStatus.SUCCEEDED)
    assert task.enqueued_by is None


@pytest.mark.django_db
def test_system_publish_still_blocks_dismissed(setup):
    """system=True keeps every guard but the human permission check — a
    dismissed advisory is never (auto-)published."""
    from django.core.exceptions import PermissionDenied

    a = setup["advisory"]
    a.state = State.DISMISSED
    a.dismissed_reason = "x"
    a.save()
    with pytest.raises(PermissionDenied):
        pub_services.publish(a, by=None, system=True)


@pytest.mark.django_db
def test_publish_rechecks_review_status_under_lock(setup):
    """TOCTOU regression (F002): a non-mature owner cannot reuse a stale
    APPROVED review to publish unreviewed content.

    Models the race deterministically. The caller holds an ``advisory`` it
    fetched while ``review_status=APPROVED`` (exactly what the view's
    ``get_object_or_404`` returns), but a concurrent ``advisory_edit`` has
    since committed ``review_status=NONE`` — a non-admin edit voids approval.
    ``publish`` must re-read the row under its ``select_for_update`` lock and
    refuse, rather than trust the stale in-memory copy (INV-AUTH-1, INV-PERM-3).
    """
    from django.core.exceptions import PermissionDenied

    advisory = setup["advisory"]  # non-mature project; member is on its team
    advisory.review_status = ReviewStatus.APPROVED
    advisory.save(update_fields=["review_status"])

    # Simulate the concurrent edit committing: .update() writes the DB row
    # WITHOUT refreshing the in-memory instance, so ``advisory`` keeps reading
    # APPROVED just like the stale object the publish view is holding.
    Advisory.objects.filter(pk=advisory.pk).update(review_status=ReviewStatus.NONE)
    assert advisory.review_status == ReviewStatus.APPROVED  # stale in memory

    with pytest.raises(PermissionDenied):
        pub_services.publish(advisory, by=setup["member"])
    assert not PublicationTask.objects.filter(advisory=advisory).exists()


@pytest.mark.django_db
def test_publish_rechecks_dismissed_state_under_lock(setup):
    """TOCTOU regression (F002): a dismiss committed after the caller fetched
    the advisory is honoured under the lock, even though the in-memory copy
    still looks publishable."""
    from django.core.exceptions import PermissionDenied

    advisory = setup["advisory"]
    # Concurrent dismiss commits to the DB; the in-memory object stays
    # non-dismissed (no refresh_from_db), like the view's stale copy.
    Advisory.objects.filter(pk=advisory.pk).update(state=State.DISMISSED, dismissed_reason="dup")
    assert advisory.state != State.DISMISSED  # stale in memory

    with pytest.raises(PermissionDenied):
        pub_services.publish(advisory, by=setup["admin"])
    assert not PublicationTask.objects.filter(advisory=advisory).exists()


@pytest.mark.django_db
def test_publish_allowed_for_non_mature_member_when_approved(setup):
    """Positive control: the under-lock re-check must not over-block. A
    non-mature project owner publishing a genuinely APPROVED advisory (DB and
    memory agree) still succeeds."""
    advisory = setup["advisory"]  # project.is_mature_publisher is False
    advisory.review_status = ReviewStatus.APPROVED
    advisory.save(update_fields=["review_status"])
    task = pub_services.publish(advisory, by=setup["member"])
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
        data={"confirm_advisory_id": setup["advisory"].advisory_id},
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

    # Verify file content reached the bare repo, bucketed by publication year.
    year = setup["advisory"].published_at.year
    verify = setup["tmp_path"] / "verify"
    _clone(str(setup["bare_repo"]), str(verify))
    osv_file = verify / "osv" / str(year) / "ECL-cccc-ffff-gggg.json"
    csaf_file = verify / "csaf" / str(year) / "ECL-cccc-ffff-gggg.json"
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
def test_withdraw_published_advisory(setup):
    """Withdrawing a published advisory re-exports OSV/CSAF with the withdrawn
    marker, flips to dismissed, and orphans the assigned CVE (INV-LIFECYCLE-4).
    The published documents stay in the repo — they are updated, not deleted."""
    import json

    from advisories import services as adv_services
    from workflows.models import OrphanCve

    advisory = setup["advisory"]
    advisory.assigned_cve_id = "CVE-2026-9999"
    advisory.save(update_fields=["assigned_cve_id"])

    # Publish first.
    task = pub_services.publish(advisory, by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    advisory.refresh_from_db()
    assert advisory.state == State.PUBLISHED

    # Withdraw (admin authority). withdraw_advisory enqueues a publication run
    # whose pinned version carries withdrawn_reason; run it directly.
    wtask = adv_services.withdraw_advisory(advisory, by=setup["admin"], reason="duplicate of X")
    pub_tasks.run_publication(wtask.pk)

    advisory.refresh_from_db()
    assert advisory.state == State.DISMISSED
    assert advisory.dismissed_from_state == State.PUBLISHED
    assert advisory.withdrawn_reason == "duplicate of X"
    assert advisory.assigned_cve_id == ""  # orphaned for cve.org rejection
    assert OrphanCve.objects.filter(previous_advisory=advisory).exists()

    # The on-disk documents stay but now carry the withdrawal.
    year = advisory.published_at.year
    verify = setup["tmp_path"] / "verify-withdraw"
    _clone(str(setup["bare_repo"]), str(verify))
    osv = json.loads((verify / "osv" / str(year) / "ECL-cccc-ffff-gggg.json").read_text())
    csaf = json.loads((verify / "csaf" / str(year) / "ECL-cccc-ffff-gggg.json").read_text())
    assert "withdrawn" in osv
    tracking = csaf["document"]["tracking"]
    assert tracking["version"] == "2"
    assert any(r["summary"] == "Advisory withdrawn" for r in tracking["revision_history"])

    # The CVE record is re-exported REJECTED (mirroring cve.org), not left
    # PUBLISHED (INV-WITHDRAW). cvelistV5 layout: cves/<year>/<bucket>/<id>.json.
    cve = json.loads((verify / "cves" / "2026" / "9xxx" / "CVE-2026-9999.json").read_text())
    assert cve["cveMetadata"]["state"] == "REJECTED"
    assert cve["containers"]["cna"]["rejectedReasons"][0]["value"] == "duplicate of X"


@pytest.mark.django_db
def test_withdrawal_retains_review_status(setup):
    """A withdrawal flips to dismissed WITHOUT the review teardown the dismiss
    services run — the advisory keeps the review_status it held at publication
    (INV-LIFECYCLE-4). Safe because the only route out of a withdrawal is
    un-withdraw → re-publication, never an editable draft; pinned here so a
    blanket ``dismissed ⇒ review_status=none`` constraint fails fast."""
    from advisories import services as adv_services

    advisory = setup["advisory"]
    advisory.review_status = ReviewStatus.APPROVED
    advisory.save(update_fields=["review_status"])

    task = pub_services.publish(advisory, by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    advisory.refresh_from_db()
    assert advisory.state == State.PUBLISHED

    wtask = adv_services.withdraw_advisory(advisory, by=setup["admin"], reason="withdrawn")
    pub_tasks.run_publication(wtask.pk)

    advisory.refresh_from_db()
    assert advisory.state == State.DISMISSED
    assert advisory.dismissed_from_state == State.PUBLISHED
    assert advisory.review_status == ReviewStatus.APPROVED  # retained, not torn down


@pytest.mark.django_db
def test_unwithdraw_reopens_to_published(setup):
    """Reopening a withdrawn advisory re-publishes it without the withdrawn
    marker, restores the CVE, and returns it to published (INV-WITHDRAW)."""
    import json

    from advisories import services as adv_services
    from publication.models import PublicationTask

    advisory = setup["advisory"]
    advisory.assigned_cve_id = "CVE-2026-9999"
    advisory.save(update_fields=["assigned_cve_id"])
    setup["project"].is_mature_publisher = True
    setup["project"].save(update_fields=["is_mature_publisher"])

    t = pub_services.publish(advisory, by=setup["admin"])
    pub_tasks.run_publication(t.pk)
    wt = adv_services.withdraw_advisory(advisory, by=setup["admin"], reason="dup")
    pub_tasks.run_publication(wt.pk)
    advisory.refresh_from_db()
    assert advisory.state == State.DISMISSED
    assert advisory.assigned_cve_id == ""

    # Un-withdraw (reopen). reopen_advisory enqueues a re-publish; run it.
    adv_services.reopen_advisory(advisory, by=setup["admin"])
    ut = PublicationTask.objects.filter(advisory=advisory).order_by("-pk").first()
    pub_tasks.run_publication(ut.pk)

    advisory.refresh_from_db()
    assert advisory.state == State.PUBLISHED
    assert advisory.withdrawn_reason == ""
    assert advisory.assigned_cve_id == "CVE-2026-9999"  # reattached

    year = advisory.published_at.year
    verify = setup["tmp_path"] / "verify-unwithdraw"
    _clone(str(setup["bare_repo"]), str(verify))
    osv = json.loads((verify / "osv" / str(year) / "ECL-cccc-ffff-gggg.json").read_text())
    assert "withdrawn" not in osv
    # The reattached CVE's record returns to PUBLISHED (INV-WITHDRAW un-withdraw).
    cve = json.loads((verify / "cves" / "2026" / "9xxx" / "CVE-2026-9999.json").read_text())
    assert cve["cveMetadata"]["state"] == "PUBLISHED"


@pytest.mark.django_db
def test_withdrawal_retry_after_failed_push(setup, monkeypatch):
    """A failed withdrawal push leaves the advisory published with
    withdrawn_reason set (and a failed task); re-running withdraw_advisory
    completes it — the failed task never blocks the retry (INV-WITHDRAW)."""
    import json

    from advisories import services as adv_services

    advisory = setup["advisory"]
    t = pub_services.publish(advisory, by=setup["admin"])
    pub_tasks.run_publication(t.pk)
    advisory.refresh_from_db()
    assert advisory.state == State.PUBLISHED

    def boom(**_kwargs):
        raise GitPublicationError("simulated push failure")

    monkeypatch.setattr(pub_tasks, "publish_files", boom)
    wt = adv_services.withdraw_advisory(advisory, by=setup["admin"], reason="dup")
    pub_tasks.run_publication(wt.pk)
    advisory.refresh_from_db()
    wt.refresh_from_db()
    assert advisory.state == State.PUBLISHED  # not flipped — push failed
    assert advisory.withdrawn_reason == "dup"  # withdrawal still pending
    assert wt.status == PublicationTaskStatus.FAILED

    # Retry: push restored, re-run withdraw_advisory → a *new* task → completes.
    monkeypatch.undo()
    wt2 = adv_services.withdraw_advisory(advisory, by=setup["admin"], reason="dup")
    assert wt2.pk != wt.pk
    pub_tasks.run_publication(wt2.pk)
    advisory.refresh_from_db()
    assert advisory.state == State.DISMISSED

    year = advisory.published_at.year
    verify = setup["tmp_path"] / "verify-retry"
    _clone(str(setup["bare_repo"]), str(verify))
    osv = json.loads((verify / "osv" / str(year) / "ECL-cccc-ffff-gggg.json").read_text())
    assert "withdrawn" in osv


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

    # Re-publishing must not move the file to a different year bucket: the
    # path is pinned to the (immutable) first-publication year, so a re-export
    # overwrites the same file rather than orphaning the original.
    def _osv_path(task):
        return PublicationArtifact.objects.get(task=task, kind=PublicationArtifact.Kind.OSV).path

    year = setup["advisory"].published_at.year
    assert _osv_path(t1) == _osv_path(t2) == f"osv/{year}/ECL-cccc-ffff-gggg.json"


# ---- Artifacts persisted -----------------------------------------------


@pytest.mark.django_db
def test_artifacts_persisted_on_success(setup):
    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    setup["advisory"].refresh_from_db()
    year = setup["advisory"].published_at.year
    artifacts = {a.kind: a for a in PublicationArtifact.objects.filter(task=task)}
    assert PublicationArtifact.Kind.OSV in artifacts
    assert PublicationArtifact.Kind.CSAF in artifacts
    assert artifacts[PublicationArtifact.Kind.OSV].path == f"osv/{year}/ECL-cccc-ffff-gggg.json"
    assert artifacts[PublicationArtifact.Kind.CSAF].path == f"csaf/{year}/ECL-cccc-ffff-gggg.json"


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
    _clone(str(setup["bare_repo"]), str(verify))
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


# ---- Prometheus metrics --------------------------------------------------
#
# prometheus_client metric objects are process-global and accumulate across the
# run, so we assert deltas (value before vs. after the publication).


@pytest.mark.django_db
def test_publication_metrics_increment_on_success(setup):
    from common import metrics

    succeeded_before = metrics.publication_total.labels(status="succeeded")._value.get()
    git_push_before = metrics.publication_stage_total.labels(stage="git_push")._value.get()
    duration_sum_before = metrics.publication_duration_seconds._sum.get()

    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    task.refresh_from_db()
    assert task.status == PublicationTaskStatus.SUCCEEDED

    assert metrics.publication_total.labels(status="succeeded")._value.get() == succeeded_before + 1
    assert (
        metrics.publication_stage_total.labels(stage="git_push")._value.get() == git_push_before + 1
    )
    assert metrics.publication_duration_seconds._sum.get() >= duration_sum_before


@pytest.mark.django_db
def test_publication_metrics_increment_on_git_failure(setup, monkeypatch):
    from common import metrics

    def boom(**_kwargs):
        raise GitPublicationError("simulated push failure")

    monkeypatch.setattr(pub_tasks, "publish_files", boom)

    failed_before = metrics.publication_total.labels(status="failed")._value.get()
    git_push_failed_before = metrics.publication_stage_total.labels(
        stage="git_push_failed"
    )._value.get()

    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    pub_tasks.run_publication(task.pk)
    task.refresh_from_db()
    assert task.status == PublicationTaskStatus.FAILED

    assert metrics.publication_total.labels(status="failed")._value.get() == failed_before + 1
    assert (
        metrics.publication_stage_total.labels(stage="git_push_failed")._value.get()
        == git_push_failed_before + 1
    )
