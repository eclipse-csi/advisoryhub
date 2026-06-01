"""Create upcoming ``AccessLogEntry`` partitions and drop expired ones.

Usage::

    python manage.py maintain_access_log_partitions --dry-run
    python manage.py maintain_access_log_partitions --retention-days 90

The scheduled Celery task ``audit.tasks.maintain_access_log_partitions`` runs
this same logic daily; this command is the manual operator equivalent. Unlike
``prune_audit`` (which deletes ledger rows), retention here is a partition drop
— O(1), no per-row DELETE.
"""

from __future__ import annotations

from django.conf import settings
from django.core.management.base import BaseCommand

from audit import partitions


class Command(BaseCommand):
    help = "Maintain AccessLogEntry monthly partitions (create upcoming, drop expired)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--retention-days",
            type=int,
            default=getattr(settings, "AUDIT_ACCESS_LOG_RETENTION_DAYS", 90),
            help="Drop monthly partitions entirely older than this horizon (default: setting).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report which partitions would be dropped without dropping them.",
        )

    def handle(self, *args, retention_days: int, dry_run: bool, **opts):
        if dry_run:
            would_drop = partitions.partitions_to_drop(retention_days)
            self.stdout.write(
                self.style.SUCCESS(
                    f"maintain_access_log_partitions (dry-run): would drop {would_drop}"
                )
            )
            return
        result = partitions.maintain(retention_days)
        self.stdout.write(
            self.style.SUCCESS(
                f"maintain_access_log_partitions: created {result['created']}, "
                f"dropped {result['dropped']}"
            )
        )
