"""Lifecycle management for the ``AccessLogEntry`` monthly range partitions.

Retention for the access log is a ``DROP PARTITION``, not a per-row ``DELETE``:
each calendar month is its own child table, so dropping a month is an O(1)
metadata operation with no dead tuples and no WAL flood. This module owns:

* :func:`ensure_upcoming` — create the current and next month's partitions
  ahead of time so inserts never fall into the DEFAULT partition.
* :func:`drop_old_partitions` — drop whole months older than the retention
  horizon (never DEFAULT, never a month that still holds in-retention rows).
* :func:`maintain` — the daily entry point (create-ahead, then drop-old),
  called by the Celery beat task and the ``maintain_access_log_partitions``
  management command.

See INV-AUDIT-5 and ``audit/migrations/0003_accesslogentry.py``.
"""

from __future__ import annotations

import logging
import re
from datetime import date, timedelta

from django.db import connection, transaction
from django.utils import timezone

log = logging.getLogger(__name__)

_PARENT = "audit_accesslogentry"
# Concrete monthly partitions only — deliberately excludes the DEFAULT
# partition (audit_accesslogentry_default), which must never be dropped.
_PARTITION_RE = re.compile(r"^audit_accesslogentry_p(\d{4})_(\d{2})$")


def _month_bounds(year: int, month: int) -> tuple[date, date]:
    """Half-open ``[start, end)`` bounds for the given calendar month."""
    start = date(year, month, 1)
    end = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    return start, end


def _partition_name(year: int, month: int) -> str:
    return f"{_PARENT}_p{year:04d}_{month:02d}"


def _next_month(year: int, month: int) -> tuple[int, int]:
    return (year + 1, 1) if month == 12 else (year, month + 1)


def _existing_partitions() -> list[tuple[str, int, int]]:
    """Return ``(name, year, month)`` for every concrete monthly partition."""
    with connection.cursor() as cur:
        cur.execute(
            "SELECT c.relname FROM pg_inherits i "
            "JOIN pg_class c ON c.oid = i.inhrelid "
            "JOIN pg_class p ON p.oid = i.inhparent "
            "WHERE p.relname = %s;",
            [_PARENT],
        )
        names = [row[0] for row in cur.fetchall()]
    out: list[tuple[str, int, int]] = []
    for name in names:
        m = _PARTITION_RE.match(name)
        if m:
            out.append((name, int(m.group(1)), int(m.group(2))))
    return out


def ensure_partition(year: int, month: int) -> str | None:
    """Create the partition for ``(year, month)`` if it does not exist.

    Returns the partition name on success (or if it already existed), or
    ``None`` if creation was skipped because rows for this range are already
    stranded in the DEFAULT partition (a sign beat was down for over a month —
    the runbook is to detach DEFAULT, relocate the rows, and recreate).
    """
    start, end = _month_bounds(year, month)
    name = _partition_name(year, month)
    sql = (
        f'CREATE TABLE IF NOT EXISTS "{name}" PARTITION OF "{_PARENT}" '
        f"FOR VALUES FROM ('{start.isoformat()}') TO ('{end.isoformat()}');"
    )
    try:
        # Per-statement atomic so a DEFAULT-conflict rolls back only this
        # create (and only this savepoint inside a test) without poisoning
        # the surrounding transaction.
        with transaction.atomic(), connection.cursor() as cur:
            cur.execute(sql)
        return name
    except Exception:
        log.warning(
            "ensure_partition: could not create %s (rows may be stranded in DEFAULT); skipping",
            name,
            exc_info=True,
        )
        return None


def ensure_upcoming(reference: date | None = None) -> list[str]:
    """Ensure the current and next month partitions exist."""
    ref = reference or timezone.now().date()
    created: list[str] = []
    for year, month in (ref.year, ref.month), _next_month(ref.year, ref.month):
        name = ensure_partition(year, month)
        if name:
            created.append(name)
    return created


def partitions_to_drop(retention_days: int) -> list[str]:
    """Names of partitions whose entire month predates the retention cutoff."""
    if retention_days <= 0:
        raise ValueError("retention_days must be positive")
    cutoff = (timezone.now() - timedelta(days=retention_days)).date()
    # ``end`` is the exclusive upper bound; dropping only when ``end <= cutoff``
    # guarantees every row in the partition is older than the horizon, so a
    # month that still holds in-retention rows is kept (partition granularity
    # means data lives a little past the exact day cutoff — acceptable).
    return [
        name
        for (name, year, month) in _existing_partitions()
        if _month_bounds(year, month)[1] <= cutoff
    ]


def drop_old_partitions(retention_days: int) -> list[str]:
    """Drop every monthly partition entirely older than the retention horizon."""
    dropped: list[str] = []
    for name in partitions_to_drop(retention_days):
        try:
            with transaction.atomic(), connection.cursor() as cur:
                cur.execute(f'DROP TABLE IF EXISTS "{name}";')
            dropped.append(name)
        except Exception:
            log.warning("drop_old_partitions: failed to drop %s; skipping", name, exc_info=True)
    return dropped


def maintain(retention_days: int) -> dict[str, list[str]]:
    """Create upcoming partitions, then drop expired ones. Idempotent."""
    created = ensure_upcoming()
    dropped = drop_old_partitions(retention_days)
    return {"created": created, "dropped": dropped}
