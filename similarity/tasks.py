"""Celery task that runs one duplicate-detection check.

Mirrors ``publication.tasks.run_publication``: refetch the row, idempotency
guard on status (re-delivery after a worker loss is safe), redacted failure
funnel. The ``rate_limit`` is the safety valve for GHSA bulk syncs, whose
single post-commit burst can enqueue one check per discovered advisory.
"""

from __future__ import annotations

import logging

from celery import shared_task

from audit.models import Action
from audit.services import record

from . import services
from .llm import LlmError
from .models import SimilarityCheck, SimilarityCheckStatus

log = logging.getLogger(__name__)


@shared_task(
    name="similarity.run_similarity_check",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    soft_time_limit=300,
    time_limit=360,
    rate_limit="6/m",
)
def run_similarity_check(self, check_id: int) -> str:
    """Run a similarity check end-to-end. Returns the check's final status."""
    try:
        check = SimilarityCheck.objects.select_related(
            "advisory", "version", "advisory__project"
        ).get(pk=check_id)
    except SimilarityCheck.DoesNotExist:
        return "missing"

    if check.status not in (SimilarityCheckStatus.QUEUED, SimilarityCheckStatus.FAILED):
        return check.status

    services.mark_running(check)
    if getattr(self, "request", None) and self.request.id:
        check.celery_task_id = self.request.id
        check.save(update_fields=["celery_task_id"])

    try:
        return services.run_check_sync(check)
    except LlmError as exc:
        return _fail(check, error=f"llm: {exc}")
    except Exception as exc:  # incl. SoftTimeLimitExceeded — operator-retryable
        log.exception("Unexpected similarity-check failure")
        return _fail(check, error=f"unexpected: {exc}")


def _fail(check: SimilarityCheck, *, error: str) -> str:
    services.mark_failed(check, error=error)
    # check.last_error is already redacted; record() redacts again.
    record(
        action=Action.SIMILARITY_CHECK_FAILED,
        advisory=check.advisory,
        new_value={"check_id": check.pk},
        metadata={"check_id": check.pk, "error": check.last_error},
    )
    return SimilarityCheckStatus.FAILED
