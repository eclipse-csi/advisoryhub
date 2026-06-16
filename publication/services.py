"""High-level publication orchestration.

Two entry points:

* :func:`publish` — invoked from the advisory page; creates a
  ``PublicationTask`` pinned to the latest :class:`AdvisoryVersion` and
  enqueues ``run_publication``.
* :func:`retry` — re-publishes after a failure. Always pins to the
  current latest version so post-failure edits are picked up.

The Celery task that actually generates files and pushes is in
``publication.tasks``. It is the only code path that flips an advisory
to ``state=published``.

Concurrency: :func:`publish` takes a row lock on the advisory and
refuses to start a new run while another task for the same advisory is
in ``queued`` or ``running``. Two near-simultaneous publishers therefore
result in exactly one push, not two racing pushes that could leave the
remote with an unpredictable ordering.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from advisories import permissions as perms
from advisories import services as advisory_services
from advisories.models import Advisory, State
from audit.models import Action
from audit.services import record
from common import metrics
from common.enqueue import safe_enqueue

from .models import PublicationTask, PublicationTaskStatus

log = logging.getLogger(__name__)


class PublicationInProgress(Exception):
    """Raised when a publish attempt collides with another in-flight run."""


@transaction.atomic
def publish(advisory: Advisory, *, by, system: bool = False) -> PublicationTask:
    """Start a publication run for ``advisory`` (current content).

    Raises :class:`PermissionDenied` if ``by`` may not publish, or
    :class:`PublicationInProgress` if a queued/running task already
    exists for the same advisory.

    ``system=True`` marks a system-initiated publish (e.g. auto-publish when
    GitHub publishes a GHSA-linked advisory): it skips the human ``can_publish``
    check (the policy decision is GitHub's, not a user's) but keeps every other
    guard — the dismissed block, the in-flight lock, and the GHSA
    ``refresh_for_publish`` gate. ``by`` is ``None`` for such runs.
    """
    if not system and not perms.can_publish(by, advisory):
        raise PermissionDenied("You cannot publish this advisory.")
    if advisory.state == State.DISMISSED:
        raise PermissionDenied("Dismissed advisories cannot be published.")

    # Serialize concurrent publishers for this advisory: take a row lock
    # so two simultaneous publish() calls execute one-after-the-other,
    # then refuse the second one if the first is still in flight.
    locked = Advisory.objects.select_for_update().filter(pk=advisory.pk).first()
    if locked is None:
        raise PermissionDenied("Advisory no longer exists.")
    in_flight = PublicationTask.objects.filter(
        advisory=advisory,
        status__in=[PublicationTaskStatus.QUEUED, PublicationTaskStatus.RUNNING],
    ).exists()
    if in_flight:
        raise PublicationInProgress(
            f"A publication run for {advisory.advisory_id} is already in progress."
        )

    # For GHSA-linked advisories we refresh metadata from GitHub *before*
    # snapshotting, so the OSV/CSAF export reflects the upstream GHSA's
    # current state. The helper raises ``PermissionDenied`` if the GHSA
    # isn't published, vanished, or has an outstanding CVE conflict —
    # those bubble up to the caller as a 4xx response.
    from advisories.models import Kind as _Kind  # local import to avoid cycle

    if advisory.kind == _Kind.GHSA_LINKED:
        from ghsa.services import refresh_for_publish

        # Refresh metadata from GitHub *before* pinning a version so the
        # OSV/CSAF export reflects the GHSA's current state. The refresh
        # path itself appends a new AdvisoryVersion if the payload moved,
        # so reloading here picks up the latest pin.
        refresh_for_publish(advisory, by=by)
        advisory.refresh_from_db()

    version = advisory_services.latest_version(advisory)
    if version is None:
        # Belt-and-braces: every advisory has v1 from the creation hook /
        # the data migration. A missing version implies a code path bypassed
        # both — refuse to publish rather than commit drifted content.
        raise PermissionDenied("Advisory has no recorded version to publish.")
    task = PublicationTask.objects.create(advisory=advisory, version=version, enqueued_by=by)
    record(
        action=Action.PUBLICATION_EXPORT_STARTED,
        actor=by,
        advisory=advisory,
        new_value={"task_id": task.pk, "version_id": version.pk, "version": version.version},
    )
    transaction.on_commit(lambda: _enqueue(task.pk))
    return task


@transaction.atomic
def retry(failed_task: PublicationTask, *, by) -> PublicationTask:
    """Retry a failed publication. Creates a *new* task pinned to the latest version.

    Reusing the original version would re-publish stale content if the
    advisory was edited to fix the validation error; we always re-pin to
    whatever the advisory's current latest version is.
    """
    if failed_task.status != PublicationTaskStatus.FAILED:
        raise PermissionDenied("Only failed publication tasks can be retried.")
    if not perms.can_publish(by, failed_task.advisory):
        raise PermissionDenied("You cannot retry this publication.")
    return publish(failed_task.advisory, by=by)


def _enqueue(task_pk: int) -> None:
    # Broker offline: safe_enqueue leaves the task 'queued' with no Celery
    # message behind it; the beat-scheduled reaper (reap_stale_tasks,
    # INV-PUB-7) fails it after PUB_TASK_STALE_QUEUED_AFTER_SECONDS so the
    # dashboard's normal Retry path applies.
    from .tasks import run_publication

    safe_enqueue(run_publication, task_pk)


def mark_running(task: PublicationTask) -> PublicationTask:
    task.status = PublicationTaskStatus.RUNNING
    task.attempts += 1
    task.started_at = timezone.now()
    task.save(update_fields=["status", "attempts", "started_at"])
    # Count the run as started here (in the worker) so every publication series
    # originates on the worker scrape target — see common.metrics.
    metrics.publication_total.labels(status="started").inc()
    return task


def mark_succeeded(task: PublicationTask, *, commit_sha: str) -> PublicationTask:
    task.status = PublicationTaskStatus.SUCCEEDED
    task.commit_sha = commit_sha
    task.finished_at = timezone.now()
    task.last_error = ""
    task.save(update_fields=["status", "commit_sha", "finished_at", "last_error"])
    metrics.publication_total.labels(status="succeeded").inc()
    _observe_duration(task)
    return task


def mark_failed(task: PublicationTask, *, error: str) -> PublicationTask:
    from audit.services import redact_secrets

    task.status = PublicationTaskStatus.FAILED
    task.finished_at = timezone.now()
    task.last_error = redact_secrets(error or "")[:8000]
    task.save(update_fields=["status", "finished_at", "last_error"])
    metrics.publication_total.labels(status="failed").inc()
    _observe_duration(task)
    return task


def _observe_duration(task: PublicationTask) -> None:
    """Record the run's wall-clock duration when both timestamps are present."""
    if task.started_at and task.finished_at:
        metrics.publication_duration_seconds.observe(
            (task.finished_at - task.started_at).total_seconds()
        )


def reap_stale_tasks(*, now: datetime | None = None) -> dict:
    """Fail ``PublicationTask`` rows orphaned in queued/running (INV-PUB-7).

    Two loss modes leave a row that both the ``run_publication`` entry guard
    and the :func:`publish` in-flight check treat as live forever:

    * a worker lost AFTER the run started (hard ``time_limit`` SIGKILL, OOM
      kill, pod eviction) — the row stays ``running`` and the redelivered
      message no-ops against the QUEUED/FAILED entry guard;
    * a broker outage at enqueue time — ``safe_enqueue`` swallowed the
      error, so the row stays ``queued`` with no Celery message at all.

    Either way :func:`publish` raises :class:`PublicationInProgress`
    indefinitely (INV-CONCURRENCY-1). Reaping flips the row to ``failed``
    through :func:`mark_failed` — never touching ``Advisory.state``
    (INV-LIFECYCLE-3) — so the normal failed→retry path applies.

    The thresholds, not the locks, are the real defense against reaping a
    live run: a ``running`` row older than
    ``PUB_TASK_STALE_RUNNING_AFTER_SECONDS`` (default 1800s, ~2.7× the 660s
    hard ``time_limit``) cannot belong to a live execution, and a ``queued``
    row older than ``PUB_TASK_STALE_QUEUED_AFTER_SECONDS`` (default 7200s,
    2× the broker's 3600s ``visibility_timeout``) is past any legitimate
    redelivery. The per-row compare-and-set in :func:`_reap_one` is
    belt-and-braces on top.
    """
    now = now or timezone.now()
    running_cutoff = now - timedelta(seconds=settings.PUB_TASK_STALE_RUNNING_AFTER_SECONDS)
    queued_cutoff = now - timedelta(seconds=settings.PUB_TASK_STALE_QUEUED_AFTER_SECONDS)
    # started_at is stamped by the same UPDATE that flips a row to running,
    # so the isnull arm is belt-and-braces for rows written by older code.
    candidates = list(
        PublicationTask.objects.filter(
            (
                Q(status=PublicationTaskStatus.RUNNING)
                & (
                    Q(started_at__lt=running_cutoff)
                    | Q(started_at__isnull=True, created_at__lt=running_cutoff)
                )
            )
            | Q(status=PublicationTaskStatus.QUEUED, created_at__lt=queued_cutoff)
        ).values_list("pk", "status")
    )
    reaped = {PublicationTaskStatus.RUNNING.value: 0, PublicationTaskStatus.QUEUED.value: 0}
    for task_pk, status in candidates:
        task = _reap_one(task_pk, expected_status=status, now=now)
        if task is None:
            continue
        reaped[status] += 1
        # Best-effort failure notification, outside the reap transaction —
        # mirrors _fail in publication.tasks. The e-mail announces the event
        # only and embeds no error text (INV-SECRET-3).
        try:
            from notifications.tasks import send_advisory_event_email

            send_advisory_event_email.delay(task.advisory_id, "publication_export_status")
        except Exception:  # pragma: no cover
            pass
    result = {
        "reaped_running": reaped[PublicationTaskStatus.RUNNING.value],
        "reaped_queued": reaped[PublicationTaskStatus.QUEUED.value],
    }
    if result["reaped_running"] or result["reaped_queued"]:
        log.info(
            "reap_stale_tasks: running=%s queued=%s",
            result["reaped_running"],
            result["reaped_queued"],
        )
    return result


def _reap_one(task_pk: int, *, expected_status: str, now: datetime) -> PublicationTask | None:
    """Compare-and-set one stale task to failed; ``None`` if it moved on.

    The status filter under ``select_for_update`` means a row finalised
    between the candidate query and this lock no longer matches and is never
    clobbered; ``skip_locked`` turns a finalisation mid-commit (or an
    overlapping reaper run) into a skip, not a wait.
    """
    with transaction.atomic():
        task = (
            PublicationTask.objects.select_for_update(skip_locked=True)
            .select_related("advisory")
            .filter(pk=task_pk, status=expected_status)
            .first()
        )
        if task is None:
            return None
        age = _stale_age_seconds(task, now=now)
        if age is None:
            return None
        stale_after = (
            settings.PUB_TASK_STALE_RUNNING_AFTER_SECONDS
            if expected_status == PublicationTaskStatus.RUNNING
            else settings.PUB_TASK_STALE_QUEUED_AFTER_SECONDS
        )
        mark_failed(task, error=_reap_error(expected_status, age))
        record(
            action=Action.PUBLICATION_TASK_REAPED,
            advisory=task.advisory,
            new_value={"task_id": task.pk},
            metadata={
                "task_id": task.pk,
                "previous_status": expected_status,
                "age_seconds": age,
                "stale_after_seconds": stale_after,
                "error": task.last_error,
            },
        )
        return task


def _stale_age_seconds(task: PublicationTask, *, now: datetime) -> int | None:
    """Seconds the row has been stuck, or ``None`` while it is still fresh."""
    if task.status == PublicationTaskStatus.RUNNING:
        anchor = task.started_at or task.created_at
        threshold = settings.PUB_TASK_STALE_RUNNING_AFTER_SECONDS
    elif task.status == PublicationTaskStatus.QUEUED:
        anchor = task.created_at
        threshold = settings.PUB_TASK_STALE_QUEUED_AFTER_SECONDS
    else:
        return None
    age = int((now - anchor).total_seconds())
    return age if age > threshold else None


def _reap_error(previous_status: str, age_seconds: int) -> str:
    cause = (
        "worker likely lost mid-run"
        if previous_status == PublicationTaskStatus.RUNNING
        else "enqueue likely lost to a broker outage"
    )
    return f"reaped: task stuck in '{previous_status}' for {age_seconds}s ({cause}); safe to retry"
