"""Tests for the ``seed_demo`` management command."""

from __future__ import annotations

import pytest
from django.core.management import call_command

from advisories.models import Advisory, AdvisoryIntakeMetadata, State
from intake.models import HoneypotSubmission
from projects.models import Project


# transaction=True so the first seed actually commits before the second
# call runs. Without it pytest-django wraps the whole test in one txn and
# the Postgres `ALTER TABLE ... DISABLE TRIGGER` we use in --reset trips
# on "pending trigger events" from the still-uncommitted first seed —
# an artefact of the test harness that never happens in real use.
@pytest.mark.django_db(transaction=True)
def test_seed_demo_then_reset_does_not_choke_on_protected_versions():
    """``--reset`` must clear advisories even after seed has created:
    * AdvisoryVersion rows PROTECTed by ReviewTask/PublicationTask FKs, and
    * audit log entries whose advisory/actor FKs SET_NULL would otherwise
      fire the append-only ``audit_log_no_update`` trigger on Postgres.
    """
    call_command("seed_demo")
    assert Advisory.objects.exists()
    assert Project.objects.exists()
    # Triage advisories are seeded too — verify the spread of states.
    assert Advisory.objects.filter(state=State.TRIAGE).count() >= 4
    # At least one seeded triage advisory is dismissed-from-intake.
    assert Advisory.objects.filter(state=State.DISMISSED, intake__isnull=False).exists()
    # Honeypot rows live in their own table now and never become advisories.
    assert HoneypotSubmission.objects.exists()
    # At least one seeded triage advisory demonstrates the admin-routing flag.
    assert AdvisoryIntakeMetadata.objects.filter(needs_admin_routing=True).exists()
    # The dashboard panel surfaces triage advisories — confirm at least one
    # is present (the panel filters by state==TRIAGE; honeypots are out of
    # band so don't pollute the count).
    assert Advisory.objects.filter(state=State.TRIAGE).exists()
    # The unsorted sentinel project exists and at least one triage advisory
    # points at it (the unrouted demo cases).
    unsorted = Project.objects.get(slug="unsorted")
    assert Advisory.objects.filter(state=State.TRIAGE, project=unsorted).exists()

    call_command("seed_demo", reset=True)

    # Reset re-seeds, so we should still have advisories/projects — but
    # the important assertion is that the reset itself didn't raise.
    assert Advisory.objects.exists()
    assert Project.objects.exists()
    assert Advisory.objects.filter(state=State.TRIAGE).exists()
    assert HoneypotSubmission.objects.exists()
