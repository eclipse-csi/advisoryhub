"""Delete audit log entries older than a configurable horizon.

Usage::

    python manage.py prune_audit --older-than-days 1825 --dry-run
    python manage.py prune_audit --older-than-days 1825

The default horizon is 1825 days (5 years). Use ``--dry-run`` to count
what *would* be removed before doing anything destructive.

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
            default=1825,
            help="Retention horizon in days (default: 1825 ≈ 5 years).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Count matching rows without deleting them.",
        )

    def handle(self, *args, older_than_days: int, dry_run: bool, **opts):
        n = prune_audit_older_than(older_than_days, dry_run=dry_run)
        verb = "would delete" if dry_run else "deleted"
        self.stdout.write(self.style.SUCCESS(f"prune_audit: {verb} {n} entries."))
