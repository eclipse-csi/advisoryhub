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

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from advisories import permissions as perms
from advisories import services as advisory_services
from advisories.models import Advisory, State
from audit.models import Action
from audit.services import record
from common.enqueue import safe_enqueue

from .models import PublicationTask, PublicationTaskStatus


class PublicationInProgress(Exception):
    """Raised when a publish attempt collides with another in-flight run."""


@transaction.atomic
def publish(advisory: Advisory, *, by) -> PublicationTask:
    """Start a publication run for ``advisory`` (current content).

    Raises :class:`PermissionDenied` if ``by`` may not publish, or
    :class:`PublicationInProgress` if a queued/running task already
    exists for the same advisory.
    """
    if not perms.can_publish(by, advisory):
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
    # Broker offline: safe_enqueue leaves the task 'queued'; the dashboard
    # surfaces it so an operator can re-trigger after fixing the broker.
    from .tasks import run_publication

    safe_enqueue(run_publication, task_pk)


def mark_running(task: PublicationTask) -> PublicationTask:
    task.status = PublicationTaskStatus.RUNNING
    task.attempts += 1
    task.started_at = timezone.now()
    task.save(update_fields=["status", "attempts", "started_at"])
    return task


def mark_succeeded(task: PublicationTask, *, commit_sha: str) -> PublicationTask:
    task.status = PublicationTaskStatus.SUCCEEDED
    task.commit_sha = commit_sha
    task.finished_at = timezone.now()
    task.last_error = ""
    task.save(update_fields=["status", "commit_sha", "finished_at", "last_error"])
    return task


def mark_failed(task: PublicationTask, *, error: str) -> PublicationTask:
    from audit.services import redact_secrets

    task.status = PublicationTaskStatus.FAILED
    task.finished_at = timezone.now()
    task.last_error = redact_secrets(error or "")[:8000]
    task.save(update_fields=["status", "finished_at", "last_error"])
    return task
