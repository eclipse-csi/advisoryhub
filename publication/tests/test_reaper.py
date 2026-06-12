"""Tests for the stale-publication-task reaper (INV-PUB-7).

No git binary needed — reaping never runs the pipeline — so unlike the
pipeline/view tests this module has no skipif(git) marker.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from advisories.models import Advisory
from audit.models import Action, AuditLogEntry
from common import metrics
from publication import services as pub_services
from publication import tasks as pub_tasks
from publication.models import PublicationTask, PublicationTaskStatus


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-rrrr-eeee-aaaa",
        summary="x",
        created_by=member,
    )
    return {"admin": admin, "member": member, "project": project, "advisory": advisory}


def _make_task(advisory, *, status, started_ago=None, created_ago=None):
    """Create a task and backdate its timestamps by the given seconds."""
    task = PublicationTask.objects.create(
        advisory=advisory, version=advisory.versions.get(version=1), status=status
    )
    if started_ago is not None:
        task.started_at = timezone.now() - timedelta(seconds=started_ago)
        task.save(update_fields=["started_at"])
    if created_ago is not None:
        # created_at is auto_now_add — backdate via queryset update.
        PublicationTask.objects.filter(pk=task.pk).update(
            created_at=timezone.now() - timedelta(seconds=created_ago)
        )
        task.refresh_from_db()
    return task


def _reap_audit_entries(advisory):
    return AuditLogEntry.objects.filter(action=Action.PUBLICATION_TASK_REAPED, advisory=advisory)


# ---- Core reaping behavior ------------------------------------------------


@pytest.mark.django_db
def test_stale_running_task_reaped(setup):
    task = _make_task(setup["advisory"], status=PublicationTaskStatus.RUNNING, started_ago=1860)
    failed_before = metrics.publication_total.labels(status="failed")._value.get()

    result = pub_services.reap_stale_tasks()

    assert result == {"reaped_running": 1, "reaped_queued": 0}
    task.refresh_from_db()
    assert task.status == PublicationTaskStatus.FAILED
    assert task.finished_at is not None
    assert task.last_error.startswith("reaped: task stuck in 'running'")
    assert "safe to retry" in task.last_error
    assert metrics.publication_total.labels(status="failed")._value.get() == failed_before + 1

    entry = _reap_audit_entries(setup["advisory"]).get()
    assert entry.metadata["previous_status"] == "running"
    assert entry.metadata["stale_after_seconds"] == 1800
    assert entry.metadata["age_seconds"] >= 1860
    assert entry.metadata["task_id"] == task.pk


@pytest.mark.django_db
def test_fresh_running_task_untouched(setup):
    task = _make_task(setup["advisory"], status=PublicationTaskStatus.RUNNING, started_ago=60)

    result = pub_services.reap_stale_tasks()

    assert result == {"reaped_running": 0, "reaped_queued": 0}
    task.refresh_from_db()
    assert task.status == PublicationTaskStatus.RUNNING
    assert not _reap_audit_entries(setup["advisory"]).exists()


@pytest.mark.django_db
def test_stale_queued_task_reaped(setup):
    task = _make_task(setup["advisory"], status=PublicationTaskStatus.QUEUED, created_ago=10800)

    result = pub_services.reap_stale_tasks()

    assert result == {"reaped_running": 0, "reaped_queued": 1}
    task.refresh_from_db()
    assert task.status == PublicationTaskStatus.FAILED
    assert task.started_at is None  # never picked up — no duration to observe
    assert task.last_error.startswith("reaped: task stuck in 'queued'")
    assert "broker outage" in task.last_error
    entry = _reap_audit_entries(setup["advisory"]).get()
    assert entry.metadata["previous_status"] == "queued"
    assert entry.metadata["stale_after_seconds"] == 7200


@pytest.mark.django_db
def test_fresh_queued_task_untouched(setup):
    # One hour old: inside the broker's 3600s visibility window — a delayed
    # redelivery must win before the reaper does.
    task = _make_task(setup["advisory"], status=PublicationTaskStatus.QUEUED, created_ago=3600)

    result = pub_services.reap_stale_tasks()

    assert result == {"reaped_running": 0, "reaped_queued": 0}
    task.refresh_from_db()
    assert task.status == PublicationTaskStatus.QUEUED


@pytest.mark.django_db
def test_terminal_rows_untouched(setup):
    succeeded = _make_task(
        setup["advisory"],
        status=PublicationTaskStatus.SUCCEEDED,
        started_ago=30 * 86400,
        created_ago=30 * 86400,
    )
    failed = _make_task(
        setup["advisory"],
        status=PublicationTaskStatus.FAILED,
        started_ago=30 * 86400,
        created_ago=30 * 86400,
    )

    result = pub_services.reap_stale_tasks()

    assert result == {"reaped_running": 0, "reaped_queued": 0}
    succeeded.refresh_from_db()
    failed.refresh_from_db()
    assert succeeded.status == PublicationTaskStatus.SUCCEEDED
    assert failed.status == PublicationTaskStatus.FAILED
    assert not _reap_audit_entries(setup["advisory"]).exists()


@pytest.mark.django_db
def test_running_with_null_started_at_reaped_by_created_at(setup):
    # Belt-and-braces arm: mark_running stamps started_at in the same UPDATE
    # that flips the status, but a row written by older code falls back to
    # created_at.
    task = _make_task(setup["advisory"], status=PublicationTaskStatus.RUNNING, created_ago=1860)
    assert task.started_at is None

    result = pub_services.reap_stale_tasks()

    assert result == {"reaped_running": 1, "reaped_queued": 0}
    task.refresh_from_db()
    assert task.status == PublicationTaskStatus.FAILED


@pytest.mark.django_db
def test_reap_does_not_touch_advisory_state(setup):
    state_before = setup["advisory"].state
    _make_task(setup["advisory"], status=PublicationTaskStatus.RUNNING, started_ago=1860)

    pub_services.reap_stale_tasks()

    setup["advisory"].refresh_from_db()
    assert setup["advisory"].state == state_before  # INV-LIFECYCLE-3
    assert setup["advisory"].published_at is None


# ---- Recovery paths -------------------------------------------------------


@pytest.mark.django_db
def test_publish_unblocked_after_reap(setup):
    # on_commit never fires inside the test transaction, so the task stays
    # genuinely queued — the exact shape of a broker-swallowed enqueue.
    task = pub_services.publish(setup["advisory"], by=setup["admin"])
    with pytest.raises(pub_services.PublicationInProgress):
        pub_services.publish(setup["advisory"], by=setup["admin"])

    PublicationTask.objects.filter(pk=task.pk).update(
        created_at=timezone.now() - timedelta(seconds=8000)
    )
    result = pub_services.reap_stale_tasks()
    assert result["reaped_queued"] == 1

    new_task = pub_services.publish(setup["advisory"], by=setup["admin"])
    assert new_task.pk != task.pk
    assert PublicationTask.objects.filter(advisory=setup["advisory"]).count() == 2


@pytest.mark.django_db
def test_admin_retry_endpoint_works_on_reaped_task(client, setup):
    task = _make_task(setup["advisory"], status=PublicationTaskStatus.RUNNING, started_ago=1860)
    pub_services.reap_stale_tasks()
    task.refresh_from_db()
    assert task.status == PublicationTaskStatus.FAILED

    client.force_login(setup["admin"])
    response = client.post(reverse("publication:retry", args=[task.pk]))

    assert response.status_code == 302
    assert PublicationTask.objects.filter(advisory=setup["advisory"]).count() == 2


# ---- Race safety / idempotency --------------------------------------------


@pytest.mark.django_db
def test_reaper_does_not_clobber_concurrently_finalised_task(setup):
    # Simulate a task finalised between the candidate query and the row lock:
    # the compare-and-set filter no longer matches and the row is left alone.
    task = _make_task(setup["advisory"], status=PublicationTaskStatus.RUNNING, started_ago=1860)
    task.status = PublicationTaskStatus.SUCCEEDED
    task.save(update_fields=["status"])

    reaped = pub_services._reap_one(
        task.pk, expected_status=PublicationTaskStatus.RUNNING, now=timezone.now()
    )

    assert reaped is None
    task.refresh_from_db()
    assert task.status == PublicationTaskStatus.SUCCEEDED
    assert not _reap_audit_entries(setup["advisory"]).exists()


@pytest.mark.django_db
def test_reaper_idempotent_second_run_noop(setup, monkeypatch):
    from notifications import tasks as notif_tasks

    calls = []
    monkeypatch.setattr(notif_tasks.send_advisory_event_email, "delay", lambda *a: calls.append(a))
    _make_task(setup["advisory"], status=PublicationTaskStatus.RUNNING, started_ago=1860)

    first = pub_services.reap_stale_tasks()
    second = pub_services.reap_stale_tasks()

    assert first == {"reaped_running": 1, "reaped_queued": 0}
    assert second == {"reaped_running": 0, "reaped_queued": 0}
    assert _reap_audit_entries(setup["advisory"]).count() == 1
    assert len(calls) == 1


@pytest.mark.django_db
def test_notification_enqueued_per_reaped_task(setup, monkeypatch):
    from notifications import tasks as notif_tasks

    calls = []
    monkeypatch.setattr(notif_tasks.send_advisory_event_email, "delay", lambda *a: calls.append(a))
    _make_task(setup["advisory"], status=PublicationTaskStatus.RUNNING, started_ago=1860)

    pub_services.reap_stale_tasks()

    assert calls == [(setup["advisory"].pk, "publication_export_status")]


# ---- Wiring ----------------------------------------------------------------


@pytest.mark.django_db
def test_beat_schedule_and_task_wrapper(settings):
    entry = settings.CELERY_BEAT_SCHEDULE["publication-task-reaper"]
    assert entry["task"] == pub_tasks.reap_stale_publication_tasks.name
    # Call the task object directly (CELERY_TASK_IGNORE_RESULT is True, so
    # .delay() would return nothing inspectable).
    assert pub_tasks.reap_stale_publication_tasks() == {
        "reaped_running": 0,
        "reaped_queued": 0,
    }


def test_threshold_knob_defaults(settings):
    # Guards against lowering a threshold below the physical constant it is
    # anchored to (660s hard time_limit / 3600s broker visibility_timeout).
    assert settings.PUB_TASK_STALE_RUNNING_AFTER_SECONDS == 1800
    assert settings.PUB_TASK_STALE_QUEUED_AFTER_SECONDS == 7200
    assert settings.PUB_TASK_STALE_RUNNING_AFTER_SECONDS > 660
    assert settings.PUB_TASK_STALE_QUEUED_AFTER_SECONDS > 3600
