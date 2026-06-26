"""Scrub PII from old triage-advisory intake sidecars and honeypot rows.

Runs against both surfaces left over from the intake fold-in:

* ``advisories.AdvisoryIntakeMetadata`` — sidecar attached to advisories
  that originated as public reports. Scrubs ``reporter_user``,
  ``reporter_display_name``, ``submitted_ip``, ``submitted_user_agent``
  in place when the advisory is past the retention horizon. The
  Advisory itself is left intact (its audit trail must remain coherent).
* ``intake.HoneypotSubmission`` — wholly opaque honeypot rows. Scrubs
  IP/UA in place; the row stays so spam analytics keep working.

The horizon is set by ``settings.INTAKE_REPORT_RETENTION_DAYS`` (default 365).

Usage::

    manage.py prune_reports
    manage.py prune_reports --dry-run
    manage.py prune_reports --advisory-id <ECL-...>   # one-off GDPR request
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from advisories.models import AdvisoryIntakeMetadata, State
from common.rls import rls_system
from intake.models import HoneypotSubmission


class Command(BaseCommand):
    help = "Scrub PII from old triage-advisory intake sidecars + honeypot submissions."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument(
            "--advisory-id",
            type=str,
            default=None,
            help="Target a single advisory's sidecar (e.g. for a one-off GDPR request).",
        )
        parser.add_argument(
            "--retention-days",
            type=int,
            default=None,
            help="Override the configured INTAKE_REPORT_RETENTION_DAYS.",
        )

    def handle(self, *args, **opts):
        # Run as a trusted system principal so the command is not RLS-filtered
        # under the production non-superuser app role (INV-CONF-2).
        with rls_system():
            return self._handle(*args, **opts)

    def _handle(self, *args, **opts):
        now = timezone.now()
        if opts["advisory_id"]:
            sidecars = AdvisoryIntakeMetadata.objects.filter(
                advisory__advisory_id=opts["advisory_id"]
            )
            honeypots = HoneypotSubmission.objects.none()
        else:
            days = opts["retention_days"] or settings.INTAKE_REPORT_RETENTION_DAYS
            cutoff = now - timedelta(days=days)
            # Scrub sidecars for advisories that are *no longer* in the
            # active triage queue — i.e. promoted (DRAFT/PUBLISHED) or
            # dismissed. Active-triage sidecars retain their PII so the
            # triager can still see who submitted what.
            sidecars = AdvisoryIntakeMetadata.objects.filter(
                advisory__state__in=(State.DRAFT, State.PUBLISHED, State.DISMISSED),
                advisory__modified_at__lt=cutoff,
                pii_cleared_at__isnull=True,
            )
            honeypots = HoneypotSubmission.objects.filter(
                submitted_at__lt=cutoff,
                pii_cleared_at__isnull=True,
            )

        sidecar_count = sidecars.count()
        honeypot_count = honeypots.count()
        self.stdout.write(
            f"Sidecars to scrub: {sidecar_count}; honeypots to scrub: {honeypot_count}"
        )
        if opts["dry_run"] or (sidecar_count + honeypot_count) == 0:
            return

        scrubbed_sidecars = sidecars.update(
            reporter_user=None,
            reporter_display_name="",
            submitted_ip=None,
            submitted_user_agent="",
            pii_cleared_at=now,
        )
        scrubbed_honeypots = honeypots.update(
            submitted_ip=None,
            submitted_user_agent="",
            honeypot_field_value="",
            pii_cleared_at=now,
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Scrubbed {scrubbed_sidecars} sidecar(s) and {scrubbed_honeypots} honeypot(s)."
            )
        )
