"""Tests for the stale-similarity-check reaper (INV-SIM-5).

Mirrors publication/tests/test_reaper.py. The reaper is DB-only janitor
work (no LLM egress), so unlike the rest of the similarity suite most
tests here deliberately run WITHOUT the enable_similarity fixture.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from advisories.models import Advisory
from audit.models import Action, AuditLogEntry
from common import metrics
from similarity import services
from similarity import tasks as sim_tasks
from similarity.models import SimilarityCheck, SimilarityCheckStatus

pytestmark = pytest.mark.django_db


@pytest.fixture
def setup(make_user, make_project):
    member = make_user(email="m@example.org")
    project = make_project("reaper-proj", team_members=[member])
    advisory = Advisory.objects.create(
        project=project,
        summary="Reflected XSS in the search box",
        details="A crafted query parameter is echoed unescaped.",
        created_by=member,
    )
    return {"member": member, "project": project, "advisory": advisory}


def _make_check(advisory, *, status, started_ago=None, created_ago=None):
    """Create a check and backdate its timestamps by the given seconds."""
    check = SimilarityCheck.objects.create(
        advisory=advisory, version=advisory.versions.get(version=1), status=status
    )
    if started_ago is not None:
        check.started_at = timezone.now() - timedelta(seconds=started_ago)
        check.save(update_fields=["started_at"])
    if created_ago is not None:
        # created_at is auto_now_add — backdate via queryset update.
        SimilarityCheck.objects.filter(pk=check.pk).update(
            created_at=timezone.now() - timedelta(seconds=created_ago)
        )
        check.refresh_from_db()
    return check


def _reap_audit_entries(advisory):
    return AuditLogEntry.objects.filter(action=Action.SIMILARITY_CHECK_REAPED, advisory=advisory)


# ---- Core reaping behavior ------------------------------------------------


def test_stale_running_check_reaped(setup):
    check = _make_check(setup["advisory"], status=SimilarityCheckStatus.RUNNING, started_ago=1860)
    failed_before = metrics.similarity_check_total.labels(status="failed")._value.get()

    result = services.reap_stale_checks()

    assert result == {"reaped_running": 1, "reaped_queued": 0}
    check.refresh_from_db()
    assert check.status == SimilarityCheckStatus.FAILED
    assert check.finished_at is not None
    assert check.last_error.startswith("reaped: check stuck in 'running'")
    assert "safe to re-run" in check.last_error
    assert metrics.similarity_check_total.labels(status="failed")._value.get() == failed_before + 1

    entry = _reap_audit_entries(setup["advisory"]).get()
    assert entry.metadata["previous_status"] == "running"
    assert entry.metadata["stale_after_seconds"] == 1800
    assert entry.metadata["age_seconds"] >= 1860
    assert entry.metadata["check_id"] == check.pk


def test_fresh_running_check_untouched(setup):
    check = _make_check(setup["advisory"], status=SimilarityCheckStatus.RUNNING, started_ago=60)

    result = services.reap_stale_checks()

    assert result == {"reaped_running": 0, "reaped_queued": 0}
    check.refresh_from_db()
    assert check.status == SimilarityCheckStatus.RUNNING
    assert not _reap_audit_entries(setup["advisory"]).exists()


def test_stale_queued_check_reaped(setup):
    check = _make_check(setup["advisory"], status=SimilarityCheckStatus.QUEUED, created_ago=10800)

    result = services.reap_stale_checks()

    assert result == {"reaped_running": 0, "reaped_queued": 1}
    check.refresh_from_db()
    assert check.status == SimilarityCheckStatus.FAILED
    assert check.started_at is None  # never picked up
    assert check.last_error.startswith("reaped: check stuck in 'queued'")
    assert "broker outage" in check.last_error
    entry = _reap_audit_entries(setup["advisory"]).get()
    assert entry.metadata["previous_status"] == "queued"
    assert entry.metadata["stale_after_seconds"] == 7200


def test_fresh_queued_check_untouched(setup):
    # One hour old: inside the broker's 3600s visibility window — a delayed
    # redelivery must win before the reaper does.
    check = _make_check(setup["advisory"], status=SimilarityCheckStatus.QUEUED, created_ago=3600)

    result = services.reap_stale_checks()

    assert result == {"reaped_running": 0, "reaped_queued": 0}
    check.refresh_from_db()
    assert check.status == SimilarityCheckStatus.QUEUED


def test_terminal_rows_untouched(setup):
    succeeded = _make_check(
        setup["advisory"],
        status=SimilarityCheckStatus.SUCCEEDED,
        started_ago=30 * 86400,
        created_ago=30 * 86400,
    )
    failed = _make_check(
        setup["advisory"],
        status=SimilarityCheckStatus.FAILED,
        started_ago=30 * 86400,
        created_ago=30 * 86400,
    )

    result = services.reap_stale_checks()

    assert result == {"reaped_running": 0, "reaped_queued": 0}
    succeeded.refresh_from_db()
    failed.refresh_from_db()
    assert succeeded.status == SimilarityCheckStatus.SUCCEEDED
    assert failed.status == SimilarityCheckStatus.FAILED
    assert not _reap_audit_entries(setup["advisory"]).exists()


def test_running_with_null_started_at_reaped_by_created_at(setup):
    # Belt-and-braces arm: mark_running stamps started_at in the same UPDATE
    # that flips the status, but a row written by older code falls back to
    # created_at.
    check = _make_check(setup["advisory"], status=SimilarityCheckStatus.RUNNING, created_ago=1860)
    assert check.started_at is None

    result = services.reap_stale_checks()

    assert result == {"reaped_running": 1, "reaped_queued": 0}
    check.refresh_from_db()
    assert check.status == SimilarityCheckStatus.FAILED


def test_reaper_runs_while_feature_disabled(setup, settings):
    # The reaper is DB-only (no LLM egress, INV-SIM-2 unaffected) and must
    # clear rows wedged from when the feature was on.
    assert settings.SIMILARITY_CHECK_ENABLED is False
    check = _make_check(setup["advisory"], status=SimilarityCheckStatus.RUNNING, started_ago=1860)

    result = services.reap_stale_checks()

    assert result == {"reaped_running": 1, "reaped_queued": 0}
    check.refresh_from_db()
    assert check.status == SimilarityCheckStatus.FAILED


# ---- Recovery paths -------------------------------------------------------


def test_rerun_unblocked_after_reap(setup, enable_similarity):
    # on_commit never fires inside the test transaction, so the check stays
    # genuinely queued — the exact shape of a broker-swallowed enqueue.
    check = services.request_check(setup["advisory"], by=setup["member"])
    with pytest.raises(services.SimilarityCheckInProgress):
        services.request_check(setup["advisory"], by=setup["member"])

    SimilarityCheck.objects.filter(pk=check.pk).update(
        created_at=timezone.now() - timedelta(seconds=8000)
    )
    result = services.reap_stale_checks()
    assert result["reaped_queued"] == 1

    new_check = services.request_check(setup["advisory"], by=setup["member"])
    assert new_check is not None
    assert new_check.pk != check.pk
    assert SimilarityCheck.objects.filter(advisory=setup["advisory"]).count() == 2


def test_panel_rerun_endpoint_works_on_reaped_check(client, setup, enable_similarity):
    check = _make_check(setup["advisory"], status=SimilarityCheckStatus.RUNNING, started_ago=1860)
    services.reap_stale_checks()
    check.refresh_from_db()
    assert check.status == SimilarityCheckStatus.FAILED

    client.force_login(setup["member"])
    response = client.post(reverse("similarity:run", args=[setup["advisory"].advisory_id]))

    assert response.status_code == 200
    assert SimilarityCheck.objects.filter(advisory=setup["advisory"]).count() == 2


# ---- Race safety / idempotency --------------------------------------------


def test_reaper_does_not_clobber_concurrently_finalised_check(setup):
    # Simulate a check finalised between the candidate query and the row lock:
    # the compare-and-set filter no longer matches and the row is left alone.
    check = _make_check(setup["advisory"], status=SimilarityCheckStatus.RUNNING, started_ago=1860)
    check.status = SimilarityCheckStatus.SUCCEEDED
    check.save(update_fields=["status"])

    reaped = services._reap_one(
        check.pk, expected_status=SimilarityCheckStatus.RUNNING, now=timezone.now()
    )

    assert reaped is None
    check.refresh_from_db()
    assert check.status == SimilarityCheckStatus.SUCCEEDED
    assert not _reap_audit_entries(setup["advisory"]).exists()


def test_reaper_idempotent_second_run_noop(setup):
    _make_check(setup["advisory"], status=SimilarityCheckStatus.RUNNING, started_ago=1860)

    first = services.reap_stale_checks()
    second = services.reap_stale_checks()

    assert first == {"reaped_running": 1, "reaped_queued": 0}
    assert second == {"reaped_running": 0, "reaped_queued": 0}
    assert _reap_audit_entries(setup["advisory"]).count() == 1


# ---- Wiring ----------------------------------------------------------------


def test_beat_schedule_and_task_wrapper(settings):
    entry = settings.CELERY_BEAT_SCHEDULE["similarity-check-reaper"]
    assert entry["task"] == sim_tasks.reap_stale_similarity_checks.name
    # Call the task object directly (CELERY_TASK_IGNORE_RESULT is True, so
    # .delay() would return nothing inspectable).
    assert sim_tasks.reap_stale_similarity_checks() == {
        "reaped_running": 0,
        "reaped_queued": 0,
    }


def test_threshold_knob_defaults(settings):
    # Guards against lowering a threshold below the physical constant it is
    # anchored to (360s hard time_limit / 3600s broker visibility_timeout).
    assert settings.SIMILARITY_CHECK_STALE_RUNNING_AFTER_SECONDS == 1800
    assert settings.SIMILARITY_CHECK_STALE_QUEUED_AFTER_SECONDS == 7200
    assert settings.SIMILARITY_CHECK_STALE_RUNNING_AFTER_SECONDS > 360
    assert settings.SIMILARITY_CHECK_STALE_QUEUED_AFTER_SECONDS > 3600
