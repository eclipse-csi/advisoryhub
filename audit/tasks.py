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
