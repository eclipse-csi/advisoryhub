"""Tests for ``intake/management/commands/prune_reports.py``.

Scrubs PII from old triage-advisory intake sidecars (post-promotion or
post-dismissal) and from old honeypot submissions.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from advisories.models import Advisory, AdvisoryIntakeMetadata, State
from intake.models import HoneypotSubmission


@pytest.mark.django_db
def test_prune_reports_scrubs_old_sidecars(make_project, settings):
    """Dismissed/draft/published sidecars past the retention horizon get
    blanked. Active-triage sidecars are left alone — the triager may still
    need the reporter info.
    """
    settings.INTAKE_REPORT_RETENTION_DAYS = 30
    project = make_project("alpha")

    # Old dismissed-from-triage: should be scrubbed.
    old_dismissed = Advisory.objects.create(
        project=project, state=State.DISMISSED, summary="d", dismissed_reason="spam"
    )
    AdvisoryIntakeMetadata.objects.create(
        advisory=old_dismissed,
        reporter_display_name="Old Reporter",
        submitted_ip="198.51.100.1",
        submitted_user_agent="curl/8",
    )
    backdate = timezone.now() - timedelta(days=60)
    Advisory.objects.filter(pk=old_dismissed.pk).update(modified_at=backdate)

    # Recent triage advisory: should be left alone (active queue).
    fresh_triage = Advisory.objects.create(project=project, state=State.TRIAGE, summary="f")
    AdvisoryIntakeMetadata.objects.create(
        advisory=fresh_triage,
        reporter_display_name="Active Reporter",
        submitted_ip="198.51.100.2",
        submitted_user_agent="curl/8",
    )

    call_command("prune_reports")

    old_sidecar = AdvisoryIntakeMetadata.objects.get(advisory=old_dismissed)
    assert old_sidecar.reporter_display_name == ""
    assert old_sidecar.submitted_ip is None
    assert old_sidecar.submitted_user_agent == ""
    assert old_sidecar.pii_cleared_at is not None

    fresh_sidecar = AdvisoryIntakeMetadata.objects.get(advisory=fresh_triage)
    assert fresh_sidecar.reporter_display_name == "Active Reporter"
    assert fresh_sidecar.submitted_ip == "198.51.100.2"
    assert fresh_sidecar.pii_cleared_at is None


@pytest.mark.django_db
def test_prune_reports_scrubs_old_honeypots(settings):
    settings.INTAKE_REPORT_RETENTION_DAYS = 30

    old = HoneypotSubmission.objects.create(
        submitted_ip="198.51.100.250",
        submitted_user_agent="python-requests/2.31",
        honeypot_field_value="https://buy-cheap.example",
    )
    HoneypotSubmission.objects.filter(pk=old.pk).update(
        submitted_at=timezone.now() - timedelta(days=60)
    )
    fresh = HoneypotSubmission.objects.create(
        submitted_ip="198.51.100.251",
        submitted_user_agent="python-requests/2.31",
        honeypot_field_value="https://buy-cheap-too.example",
    )

    call_command("prune_reports")

    old.refresh_from_db()
    assert old.submitted_ip is None
    assert old.submitted_user_agent == ""
    assert old.honeypot_field_value == ""
    assert old.pii_cleared_at is not None

    fresh.refresh_from_db()
    assert fresh.submitted_ip == "198.51.100.251"
    assert fresh.pii_cleared_at is None


@pytest.mark.django_db
def test_prune_reports_dry_run_does_not_scrub(make_project, settings):
    settings.INTAKE_REPORT_RETENTION_DAYS = 30
    project = make_project("alpha")
    old = Advisory.objects.create(
        project=project, state=State.DISMISSED, summary="d", dismissed_reason="spam"
    )
    AdvisoryIntakeMetadata.objects.create(
        advisory=old, reporter_display_name="Old", submitted_ip="198.51.100.9"
    )
    Advisory.objects.filter(pk=old.pk).update(modified_at=timezone.now() - timedelta(days=60))

    call_command("prune_reports", "--dry-run")

    sidecar = AdvisoryIntakeMetadata.objects.get(advisory=old)
    assert sidecar.reporter_display_name == "Old"
    assert sidecar.submitted_ip == "198.51.100.9"
    assert sidecar.pii_cleared_at is None
