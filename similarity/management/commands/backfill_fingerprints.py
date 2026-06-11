"""Backfill LLM fingerprints for the existing advisory corpus.

Usage::

    python manage.py backfill_fingerprints --dry-run
    python manage.py backfill_fingerprints --limit 100
    python manage.py backfill_fingerprints --project glassfish

One LLM call per advisory whose fingerprint is missing or stale, so the
command refuses to run while ``SIMILARITY_CHECK_ENABLED`` is off — enabling
the flag is the explicit consent for advisory content to leave the
deployment (INV-SIM-2). Going forward the corpus stays warm on its own:
every duplicate check persists the checked advisory's fingerprint.
"""

from __future__ import annotations

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from advisories.models import Advisory
from similarity import llm, services
from similarity.models import AdvisoryFingerprint


class Command(BaseCommand):
    help = "Generate missing/stale LLM fingerprints for existing advisories."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Stop after generating this many fingerprints (0 = no limit).",
        )
        parser.add_argument(
            "--project",
            default="",
            help="Restrict to one project slug.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be generated without calling the LLM.",
        )

    def handle(self, *args, limit: int, project: str, dry_run: bool, **opts):
        if not settings.SIMILARITY_CHECK_ENABLED:
            raise CommandError(
                "SIMILARITY_CHECK_ENABLED is off; refusing to send advisory "
                "content to the LLM provider."
            )

        queryset = Advisory.objects.select_related("project").order_by("pk")
        if project:
            queryset = queryset.filter(project__slug=project)

        client = None if dry_run else llm.get_client()
        counters = {"generated": 0, "skipped_fresh": 0, "skipped_empty": 0, "failed": 0}

        for advisory in queryset.iterator():
            if limit and counters["generated"] >= limit:
                break
            subset = services._live_hash_subset(advisory)
            if not services.has_meaningful_content(subset):
                counters["skipped_empty"] += 1
                continue
            content_hash = services.payload_content_hash(subset)
            existing = AdvisoryFingerprint.objects.filter(advisory=advisory).first()
            if existing is not None and existing.content_hash == content_hash:
                counters["skipped_fresh"] += 1
                continue
            if dry_run:
                counters["generated"] += 1
                continue
            try:
                services.ensure_fingerprint(advisory, subset, client=client)
            except llm.LlmError as exc:
                counters["failed"] += 1
                self.stderr.write(f"{advisory.advisory_id}: {exc}")
            else:
                counters["generated"] += 1

        verb = "would generate" if dry_run else "generated"
        self.stdout.write(
            self.style.SUCCESS(
                f"backfill_fingerprints: {verb} {counters['generated']}, "
                f"fresh {counters['skipped_fresh']}, empty {counters['skipped_empty']}, "
                f"failed {counters['failed']}."
            )
        )
