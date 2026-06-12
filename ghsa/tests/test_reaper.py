"""Tests for the stale-CVE-push reaper (INV-GHSA-2).

Mirrors the publication/similarity reaper tests, plus the ghsa-specific
guarded advisory-badge flip and the pinned GhsaSyncRun atomicity property
(sync runs cannot strand in RUNNING, so they need no reaper).
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from advisories.models import Advisory, GhsaCvePushStatus, Kind
from audit.models import Action, AuditLogEntry
from ghsa import services
from ghsa import tasks as ghsa_tasks
from ghsa.models import GhsaCvePushTask, GhsaCvePushTaskStatus, GhsaSyncRun

pytestmark = pytest.mark.django_db


@pytest.fixture
def advisory(make_project):
    project = make_project("reaper-proj")
    return Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-reap-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
        assigned_cve_id="CVE-2026-0042",
        summary="x",
    )


def _make_push_task(advisory, *, status, started_ago=None, created_ago=None, pending=True):
    """Create a push task (advisory badge set to 'pending' like enqueue does)."""
    if pending:
        advisory.ghsa_cve_push_status = GhsaCvePushStatus.PENDING
        advisory.save(update_fields=["ghsa_cve_push_status", "modified_at"])
    task = GhsaCvePushTask.objects.create(advisory=advisory, cve_id="CVE-2026-0042", status=status)
    if started_ago is not None:
        task.started_at = timezone.now() - timedelta(seconds=started_ago)
        task.save(update_fields=["started_at"])
    if created_ago is not None:
        # created_at is auto_now_add — backdate via queryset update.
        GhsaCvePushTask.objects.filter(pk=task.pk).update(
            created_at=timezone.now() - timedelta(seconds=created_ago)
        )
        task.refresh_from_db()
    return task


def _reap_audit_entries(advisory):
    return AuditLogEntry.objects.filter(action=Action.GHSA_CVE_PUSH_REAPED, advisory=advisory)


# ---- Core reaping behavior ------------------------------------------------


def test_stale_running_push_reaped_and_badge_corrected(advisory):
    task = _make_push_task(advisory, status=GhsaCvePushTaskStatus.RUNNING, started_ago=1860)

    result = services.reap_stale_cve_push_tasks()

    assert result == {"reaped_push_running": 1, "reaped_push_queued": 0}
    task.refresh_from_db()
    assert task.status == GhsaCvePushTaskStatus.FAILED
    assert task.finished_at is not None
    assert task.last_error.startswith("reaped: push stuck in 'running'")
    advisory.refresh_from_db()
    assert advisory.ghsa_cve_push_status == GhsaCvePushStatus.FAILED
    assert advisory.ghsa_cve_push_attempted_at is not None

    entry = _reap_audit_entries(advisory).get()
    assert entry.metadata["previous_status"] == "running"
    assert entry.metadata["stale_after_seconds"] == 1800
    assert entry.metadata["age_seconds"] >= 1860
    assert entry.metadata["advisory_status_updated"] is True
    assert entry.metadata["task_id"] == task.pk


def test_stale_queued_push_reaped_and_badge_corrected(advisory):
    task = _make_push_task(advisory, status=GhsaCvePushTaskStatus.QUEUED, created_ago=10800)

    result = services.reap_stale_cve_push_tasks()

    assert result == {"reaped_push_running": 0, "reaped_push_queued": 1}
    task.refresh_from_db()
    assert task.status == GhsaCvePushTaskStatus.FAILED
    assert task.started_at is None  # never picked up
    assert "broker outage" in task.last_error
    advisory.refresh_from_db()
    assert advisory.ghsa_cve_push_status == GhsaCvePushStatus.FAILED
    entry = _reap_audit_entries(advisory).get()
    assert entry.metadata["stale_after_seconds"] == 7200


def test_fresh_rows_untouched(advisory):
    running = _make_push_task(advisory, status=GhsaCvePushTaskStatus.RUNNING, started_ago=60)
    queued = _make_push_task(advisory, status=GhsaCvePushTaskStatus.QUEUED, created_ago=3600)

    result = services.reap_stale_cve_push_tasks()

    assert result == {"reaped_push_running": 0, "reaped_push_queued": 0}
    running.refresh_from_db()
    queued.refresh_from_db()
    assert running.status == GhsaCvePushTaskStatus.RUNNING
    assert queued.status == GhsaCvePushTaskStatus.QUEUED
    advisory.refresh_from_db()
    assert advisory.ghsa_cve_push_status == GhsaCvePushStatus.PENDING
    assert not _reap_audit_entries(advisory).exists()


def test_terminal_rows_untouched(advisory):
    succeeded = _make_push_task(
        advisory,
        status=GhsaCvePushTaskStatus.SUCCEEDED,
        started_ago=30 * 86400,
        created_ago=30 * 86400,
        pending=False,
    )
    failed = _make_push_task(
        advisory,
        status=GhsaCvePushTaskStatus.FAILED,
        started_ago=30 * 86400,
        created_ago=30 * 86400,
        pending=False,
    )

    result = services.reap_stale_cve_push_tasks()

    assert result == {"reaped_push_running": 0, "reaped_push_queued": 0}
    succeeded.refresh_from_db()
    failed.refresh_from_db()
    assert succeeded.status == GhsaCvePushTaskStatus.SUCCEEDED
    assert failed.status == GhsaCvePushTaskStatus.FAILED


def test_running_with_null_started_at_reaped_by_created_at(advisory):
    task = _make_push_task(advisory, status=GhsaCvePushTaskStatus.RUNNING, created_ago=1860)
    assert task.started_at is None

    result = services.reap_stale_cve_push_tasks()

    assert result["reaped_push_running"] == 1
    task.refresh_from_db()
    assert task.status == GhsaCvePushTaskStatus.FAILED


# ---- Guarded advisory-badge flip -------------------------------------------


def test_badge_not_clobbered_when_newer_task_in_flight(advisory):
    stale = _make_push_task(advisory, status=GhsaCvePushTaskStatus.RUNNING, started_ago=1860)
    # A newer enqueue re-set the badge to 'pending' — that pending belongs
    # to the fresh queued task, not the stale one being reaped.
    fresh = _make_push_task(advisory, status=GhsaCvePushTaskStatus.QUEUED)

    result = services.reap_stale_cve_push_tasks()

    assert result == {"reaped_push_running": 1, "reaped_push_queued": 0}
    stale.refresh_from_db()
    fresh.refresh_from_db()
    assert stale.status == GhsaCvePushTaskStatus.FAILED
    assert fresh.status == GhsaCvePushTaskStatus.QUEUED
    advisory.refresh_from_db()
    assert advisory.ghsa_cve_push_status == GhsaCvePushStatus.PENDING
    entry = _reap_audit_entries(advisory).get()
    assert entry.metadata["advisory_status_updated"] is False


def test_badge_not_clobbered_when_already_succeeded(advisory):
    stale = _make_push_task(advisory, status=GhsaCvePushTaskStatus.RUNNING, started_ago=1860)
    # A newer task already succeeded and stamped the advisory.
    advisory.ghsa_cve_push_status = GhsaCvePushStatus.SUCCEEDED
    advisory.save(update_fields=["ghsa_cve_push_status", "modified_at"])

    services.reap_stale_cve_push_tasks()

    stale.refresh_from_db()
    assert stale.status == GhsaCvePushTaskStatus.FAILED
    advisory.refresh_from_db()
    assert advisory.ghsa_cve_push_status == GhsaCvePushStatus.SUCCEEDED


def test_conflict_fields_untouched_by_reap(advisory):
    detected = timezone.now()
    advisory.ghsa_cve_conflict_detected_at = detected
    advisory.ghsa_cve_conflict_ghsa_value = "CVE-2025-9999"
    advisory.save(update_fields=["ghsa_cve_conflict_detected_at", "ghsa_cve_conflict_ghsa_value"])
    _make_push_task(advisory, status=GhsaCvePushTaskStatus.RUNNING, started_ago=1860)

    services.reap_stale_cve_push_tasks()

    advisory.refresh_from_db()
    assert advisory.ghsa_cve_conflict_detected_at == detected
    assert advisory.ghsa_cve_conflict_ghsa_value == "CVE-2025-9999"


# ---- Race safety / idempotency --------------------------------------------


def test_reaper_does_not_clobber_concurrently_finalised_task(advisory):
    task = _make_push_task(advisory, status=GhsaCvePushTaskStatus.RUNNING, started_ago=1860)
    task.status = GhsaCvePushTaskStatus.SUCCEEDED
    task.save(update_fields=["status"])

    reaped = services._reap_one_push(
        task.pk, expected_status=GhsaCvePushTaskStatus.RUNNING, now=timezone.now()
    )

    assert reaped is None
    task.refresh_from_db()
    assert task.status == GhsaCvePushTaskStatus.SUCCEEDED
    assert not _reap_audit_entries(advisory).exists()


def test_reaper_idempotent_second_run_noop(advisory):
    _make_push_task(advisory, status=GhsaCvePushTaskStatus.RUNNING, started_ago=1860)

    first = services.reap_stale_cve_push_tasks()
    second = services.reap_stale_cve_push_tasks()

    assert first["reaped_push_running"] == 1
    assert second == {"reaped_push_running": 0, "reaped_push_queued": 0}
    assert _reap_audit_entries(advisory).count() == 1


def test_reaper_runs_while_feature_disabled(advisory, settings):
    # DB-only janitor work — no GitHub egress; must clear rows wedged from
    # when the feature was on.
    assert settings.GHSA_FEATURE_ENABLED is False
    task = _make_push_task(advisory, status=GhsaCvePushTaskStatus.RUNNING, started_ago=1860)

    result = services.reap_stale_cve_push_tasks()

    assert result["reaped_push_running"] == 1
    task.refresh_from_db()
    assert task.status == GhsaCvePushTaskStatus.FAILED


# ---- GhsaSyncRun needs no reaper (atomicity pinned) -------------------------


def test_interrupted_sync_leaves_no_stranded_running_run(make_project, monkeypatch):
    """sync_ghsas_for_project is transaction.atomic: an escaping exception
    rolls back the RUNNING run row instead of stranding it — the property
    that makes a GhsaSyncRun reaper unnecessary (INV-GHSA-2)."""
    from projects.models import ProjectGitHubRepository

    project = make_project("sync-crash-proj")
    ProjectGitHubRepository.objects.create(
        project=project, owner="eclipse", name="example", last_seen_in_pmi_at=timezone.now()
    )

    class _ExplodingClient:
        def list_repo_advisories(self, *args, **kwargs):
            raise RuntimeError("boom")  # NOT a GitHubApiError — escapes the per-repo catch

    monkeypatch.setattr(services, "get_client", lambda: _ExplodingClient())

    with pytest.raises(RuntimeError):
        services.sync_ghsas_for_project(project, by=None)

    assert GhsaSyncRun.objects.count() == 0


# ---- Wiring ----------------------------------------------------------------


def test_beat_schedule_and_task_wrapper(settings):
    entry = settings.CELERY_BEAT_SCHEDULE["ghsa-cve-push-reaper"]
    assert entry["task"] == ghsa_tasks.reap_stale_cve_push_tasks.name
    assert ghsa_tasks.reap_stale_cve_push_tasks() == {
        "reaped_push_running": 0,
        "reaped_push_queued": 0,
    }


def test_threshold_knob_defaults(settings):
    # Guards against lowering a threshold below the constant it is anchored
    # to (the GitHub client's bounded per-call timeouts / the broker's
    # 3600s visibility_timeout).
    assert settings.GHSA_CVE_PUSH_STALE_RUNNING_AFTER_SECONDS == 1800
    assert settings.GHSA_CVE_PUSH_STALE_QUEUED_AFTER_SECONDS == 7200
    assert settings.GHSA_CVE_PUSH_STALE_QUEUED_AFTER_SECONDS > 3600
