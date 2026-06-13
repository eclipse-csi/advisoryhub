"""Delete audit log entries older than a configurable horizon.

Usage::

    python manage.py prune_audit --older-than-days 3650 --dry-run
    python manage.py prune_audit --older-than-days 3650

The default horizon is 3650 days (10 years). Use ``--dry-run`` to count
what *would* be removed before doing anything destructive.

Every non-dry-run invocation records an ``AUDIT_PRUNED`` entry on the
durable ledger (horizon, exact cutoff, deleted row count, optional
``--reason``), so the sweep itself stays in the immutable history.

This bypasses the append-only Postgres triggers via
``SET LOCAL session_replication_role = replica`` for the duration of
the transaction, which is the supported way to allow a one-shot
maintenance operation through. Confirm with `EXPLAIN ANALYZE
DELETE …` on a representative dataset first if you're worried about
runtime — the operation is one-shot O(N) over the matching rows.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from audit.retention import prune_audit_older_than


class Command(BaseCommand):
    help = "Delete audit log entries older than the configured horizon."

    def add_arguments(self, parser):
        parser.add_argument(
            "--older-than-days",
            type=int,
            default=3650,
            help="Retention horizon in days (default: 3650 ≈ 10 years).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Count matching rows without deleting them.",
        )
        parser.add_argument(
            "--reason",
            default="",
            help="Justification recorded on the AUDIT_PRUNED audit entry.",
        )

    def handle(self, *args, older_than_days: int, dry_run: bool, reason: str, **opts):
        n = prune_audit_older_than(older_than_days, dry_run=dry_run, reason=reason)
        verb = "would delete" if dry_run else "deleted"
        self.stdout.write(self.style.SUCCESS(f"prune_audit: {verb} {n} entries."))
