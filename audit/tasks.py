"""Celery tasks for audit retention.

Currently just the daily access-log partition maintenance. The durable
``AuditLogEntry`` ledger is *not* on a schedule — it is trimmed only by the
manual ``prune_audit`` command, by design (see INV-AUDIT-1 / INV-AUDIT-5).
"""

from __future__ import annotations

import logging

from celery import shared_task
from django.conf import settings

from . import partitions

log = logging.getLogger(__name__)


@shared_task(name="audit.tasks.refresh_backlog_gauges")
def refresh_backlog_gauges() -> dict:
    """Refresh the ``advisoryhub_backlog`` gauge from live DB counts.

    Runs in the worker (so the gauge lands on the worker's Prometheus exporter,
    see common.celery_metrics). A periodic ``.set()`` keeps the published value
    accurate without a scrape-time DB collector, which would be invisible under
    gunicorn multiprocess mode. The queries mirror the Admin Console inbox strip
    (admin_console/views/inbox.py) so the gauge and the UI never disagree.
    """
    from advisories.models import Advisory, State
    from common import metrics
    from publication.models import PublicationTask, PublicationTaskStatus
    from workflows.models import (
        CveRequestStatus,
        CveRequestTask,
        OrphanCve,
        OrphanCveReassignmentStatus,
        OrphanCveReassignmentTask,
        OrphanCveStatus,
        ReviewTask,
        ReviewTaskStatus,
    )

    counts = {
        "pub_failed": PublicationTask.objects.filter(status=PublicationTaskStatus.FAILED).count(),
        "cve_open": CveRequestTask.objects.filter(status=CveRequestStatus.QUEUED).count(),
        "review_open": ReviewTask.objects.filter(status=ReviewTaskStatus.OPEN).count(),
        "triage": Advisory.objects.filter(state=State.TRIAGE).count(),
        "triage_routing": Advisory.objects.filter(
            state=State.TRIAGE, intake__needs_admin_routing=True
        ).count(),
        "orphan": OrphanCve.objects.filter(status=OrphanCveStatus.ORPHANED).count(),
        "reassignment": OrphanCveReassignmentTask.objects.filter(
            status=OrphanCveReassignmentStatus.QUEUED
        ).count(),
    }
    for queue, value in counts.items():
        metrics.backlog.labels(queue=queue).set(value)
    return counts


@shared_task(name="audit.tasks.maintain_access_log_partitions")
def maintain_access_log_partitions() -> dict:
    """Daily: create upcoming ``AccessLogEntry`` partitions and drop expired ones.

    No-ops when ``AUDIT_ACCESS_LOG_RETENTION_ENABLED`` is False so the beat
    entry can ship present-but-dormant.
    """
    if not getattr(settings, "AUDIT_ACCESS_LOG_RETENTION_ENABLED", True):
        return {"skipped": "AUDIT_ACCESS_LOG_RETENTION_ENABLED is False"}
    days = getattr(settings, "AUDIT_ACCESS_LOG_RETENTION_DAYS", 90)
    result = partitions.maintain(days)
    log.info(
        "maintain_access_log_partitions: created=%s dropped=%s (retention=%sd)",
        result["created"],
        result["dropped"],
        days,
    )
    return result
