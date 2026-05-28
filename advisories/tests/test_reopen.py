"""Tests for the reopen-advisory flow.

Covers ``advisories.services.reopen_advisory``, ``can_reopen`` permission
gating, the dismiss-time ``dismissed_from_state`` stamp, the auto-restore
of cancelled ``CveRequestTask`` rows, and the three orphan dispositions
(direct reassign, queued admin task, no-op) the reopen path orchestrates.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from advisories import permissions as perms
from advisories import services
from advisories.models import Advisory, State
from audit.models import Action, AuditLogEntry
from workflows import services as wf
from workflows.models import (
    CveRequestStatus,
    OrphanCve,
    OrphanCveReassignmentStatus,
    OrphanCveReassignmentTask,
    OrphanCveStatus,
)


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    outsider = make_user(email="o@example.org")
    project = make_project("alpha", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x", created_by=member)
    return {
        "admin": admin,
        "member": member,
        "outsider": outsider,
        "project": project,
        "advisory": advisory,
    }


def _dismiss_draft(setup, *, advisory=None, reason="duplicate"):
    """Drive the draft-dismiss view's logic in-process so we have a
    DISMISSED row with ``dismissed_from_state`` stamped, plus any CVE and
    review side-effects executed (mirrors the real view's atomic block)."""
    from django.db import transaction

    from audit.models import Action as A
    from audit.services import record
    from workflows.services import (
        cancel_open_cve_request,
        cancel_pending_review,
        unassign_cve,
    )

    target = advisory or setup["advisory"]
    with transaction.atomic():
        previous_state = target.state
        target.state = State.DISMISSED
        target.dismissed_reason = reason
        target.dismissed_from_state = previous_state
        target.save()
        record(
            action=A.ADVISORY_DISMISSED,
            actor=setup["member"],
            advisory=target,
            previous_value=previous_state,
            new_value=State.DISMISSED,
        )
        cancel_open_cve_request(target, by=setup["member"], reason=f"Advisory dismissed: {reason}")
        cancel_pending_review(target, by=setup["member"], reason=f"Advisory dismissed: {reason}")
        if target.assigned_cve_id:
            unassign_cve(target, by=setup["admin"], reason=f"Advisory dismissed: {reason}")
    target.refresh_from_db()
    return target


# ---------------------- can_reopen predicate --------------------------------


@pytest.mark.django_db
def test_can_reopen_only_when_dismissed_and_owner(setup):
    advisory = setup["advisory"]
    # Draft state — owner can edit but not reopen (it's not dismissed).
    assert perms.can_reopen(setup["member"], advisory) is False
    _dismiss_draft(setup)
    # Now dismissed — owner can reopen.
    assert perms.can_reopen(setup["member"], advisory) is True
    # Admin always counts as owner.
    assert perms.can_reopen(setup["admin"], advisory) is True


@pytest.mark.django_db
def test_can_reopen_blocked_for_outsider(setup):
    _dismiss_draft(setup)
    assert perms.can_reopen(setup["outsider"], setup["advisory"]) is False


# ---------------------- reopen_advisory service -----------------------------


@pytest.mark.django_db
def test_dismiss_draft_stamps_dismissed_from_state(setup):
    advisory = _dismiss_draft(setup)
    assert advisory.dismissed_from_state == State.DRAFT


@pytest.mark.django_db
def test_dismiss_triage_stamps_dismissed_from_state(make_user, make_project):
    from advisories.models import AdvisoryIntakeMetadata

    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    advisory = Advisory.objects.create(project=project, state=State.TRIAGE, summary="x")
    AdvisoryIntakeMetadata.objects.create(advisory=advisory)

    services.dismiss_triage(advisory, by=member, reason="spam")
    advisory.refresh_from_db()
    assert advisory.state == State.DISMISSED
    assert advisory.dismissed_from_state == State.TRIAGE


@pytest.mark.django_db
def test_reopen_draft_dismissed_returns_to_draft(setup):
    advisory = _dismiss_draft(setup)
    reopened = services.reopen_advisory(advisory, by=setup["member"])
    assert reopened.state == State.DRAFT
    # dismissed_reason and dismissed_from_state stay as historical metadata.
    assert reopened.dismissed_reason == "duplicate"
    assert reopened.dismissed_from_state == State.DRAFT


@pytest.mark.django_db
def test_reopen_triage_dismissed_returns_to_triage(make_user, make_project):
    from advisories.models import AdvisoryIntakeMetadata

    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    advisory = Advisory.objects.create(project=project, state=State.TRIAGE, summary="x")
    AdvisoryIntakeMetadata.objects.create(advisory=advisory)
    services.dismiss_triage(advisory, by=member, reason="spam")
    advisory.refresh_from_db()

    reopened = services.reopen_advisory(advisory, by=member)
    assert reopened.state == State.TRIAGE


@pytest.mark.django_db
def test_reopen_rejects_non_dismissed(setup):
    # ``can_reopen`` already encodes the state requirement (state must be
    # DISMISSED), so attempting reopen on a draft fails the permission gate
    # rather than the inner state check.
    with pytest.raises(PermissionDenied):
        services.reopen_advisory(setup["advisory"], by=setup["member"])


@pytest.mark.django_db
def test_reopen_blocked_for_outsider(setup):
    _dismiss_draft(setup)
    with pytest.raises(PermissionDenied):
        services.reopen_advisory(setup["advisory"], by=setup["outsider"])


@pytest.mark.django_db
def test_reopen_emits_audit(setup):
    advisory = _dismiss_draft(setup)
    services.reopen_advisory(advisory, by=setup["member"])
    assert AuditLogEntry.objects.filter(action=Action.ADVISORY_REOPENED).exists()
    # The state-change row mirrors the reopened audit for the
    # ``ADVISORY_STATE_CHANGED`` time-series.
    state_changes = AuditLogEntry.objects.filter(
        action=Action.ADVISORY_STATE_CHANGED, advisory=advisory
    ).order_by("created_at")
    assert state_changes.last().new_value == {"state": State.DRAFT}


# ---------------------- CveRequestTask auto-restore -------------------------


@pytest.mark.django_db
def test_reopen_restores_cancelled_cve_request(setup):
    advisory = setup["advisory"]
    wf.request_cve(advisory, by=setup["member"])
    _dismiss_draft(setup)
    # The dismiss path auto-cancelled the queued task.
    assert advisory.cve_requests.filter(status=CveRequestStatus.CANCELLED).count() == 1
    services.reopen_advisory(advisory, by=setup["member"])
    advisory.refresh_from_db()
    # A fresh QUEUED request now sits next to the (still-historical) cancelled one.
    assert advisory.cve_requests.filter(status=CveRequestStatus.QUEUED).count() == 1
    assert advisory.cve_requests.filter(status=CveRequestStatus.CANCELLED).count() == 1


@pytest.mark.django_db
def test_reopen_no_cve_request_restore_when_none_was_open(setup):
    advisory = _dismiss_draft(setup)
    services.reopen_advisory(advisory, by=setup["member"])
    advisory.refresh_from_db()
    assert advisory.cve_requests.count() == 0


@pytest.mark.django_db
def test_reopen_no_cve_request_restore_for_triage_target(make_user, make_project):
    from advisories.models import AdvisoryIntakeMetadata

    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    advisory = Advisory.objects.create(project=project, state=State.TRIAGE, summary="x")
    AdvisoryIntakeMetadata.objects.create(advisory=advisory)
    services.dismiss_triage(advisory, by=member, reason="spam")
    advisory.refresh_from_db()

    services.reopen_advisory(advisory, by=member)
    advisory.refresh_from_db()
    # Triage advisories never have CveRequestTask rows in the first place.
    assert advisory.cve_requests.count() == 0


# ---------------------- Orphan CVE reassignment -----------------------------


def _reserve_then_dismiss_with_cve(setup, cve_id="CVE-2026-9999"):
    advisory = setup["advisory"]
    task = wf.request_cve(advisory, by=setup["member"])
    wf.transition_cve_request(
        task, by=setup["admin"], new_status=CveRequestStatus.RESERVED, cve_id=cve_id
    )
    advisory.refresh_from_db()
    return _dismiss_draft(setup)


@pytest.mark.django_db
def test_reopen_with_orphaned_orphan_reattaches_cve_directly(setup):
    advisory = _reserve_then_dismiss_with_cve(setup)
    orphan = OrphanCve.objects.get(previous_advisory=advisory)
    assert orphan.status == OrphanCveStatus.ORPHANED

    services.reopen_advisory(advisory, by=setup["admin"])
    advisory.refresh_from_db()
    orphan.refresh_from_db()
    assert advisory.assigned_cve_id == "CVE-2026-9999"
    assert orphan.status == OrphanCveStatus.REASSIGNED
    # No admin reassignment task — direct reattachment doesn't need one.
    assert OrphanCveReassignmentTask.objects.filter(orphan_cve=orphan).count() == 0
    assert AuditLogEntry.objects.filter(action=Action.CVE_REASSIGNED_FROM_ORPHAN).exists()


@pytest.mark.django_db
def test_reopen_with_marked_rejected_orphan_creates_reassignment_task(setup):
    advisory = _reserve_then_dismiss_with_cve(setup)
    orphan = OrphanCve.objects.get(previous_advisory=advisory)
    wf.mark_orphan_rejected(orphan, by=setup["admin"], notes="cve.org ticket 42")
    orphan.refresh_from_db()
    assert orphan.status == OrphanCveStatus.MARKED_REJECTED

    services.reopen_advisory(advisory, by=setup["admin"])
    advisory.refresh_from_db()
    orphan.refresh_from_db()
    # Advisory is back in draft *without* a CVE — admin work pending.
    assert advisory.state == State.DRAFT
    assert advisory.assigned_cve_id == ""
    # Orphan stays MARKED_REJECTED until admin resolves the task.
    assert orphan.status == OrphanCveStatus.MARKED_REJECTED
    tasks = OrphanCveReassignmentTask.objects.filter(orphan_cve=orphan)
    assert tasks.count() == 1
    assert tasks.first().status == OrphanCveReassignmentStatus.QUEUED
    assert AuditLogEntry.objects.filter(action=Action.ORPHAN_REASSIGNMENT_REQUESTED).exists()


@pytest.mark.django_db
def test_reopen_noop_when_latest_orphan_already_reassigned(setup):
    """An orphan already in REASSIGNED status (e.g. because a prior reopen
    already gave the CVE back, then admin yanked it again) is the no-op
    case: reopen flips the state but leaves the CVE field as-is."""
    advisory = _reserve_then_dismiss_with_cve(setup)
    orphan = OrphanCve.objects.get(previous_advisory=advisory)
    # Pretend the orphan was reclaimed via a prior reopen cycle.
    orphan.status = OrphanCveStatus.REASSIGNED
    orphan.save(update_fields=["status"])

    services.reopen_advisory(advisory, by=setup["admin"])
    advisory.refresh_from_db()
    assert advisory.state == State.DRAFT
    # No automatic CVE reattachment from a REASSIGNED orphan — owner must
    # re-request a fresh CVE if they want one.
    assert advisory.assigned_cve_id == ""


@pytest.mark.django_db
def test_reopen_no_orphan_is_noop(setup):
    advisory = _dismiss_draft(setup)
    services.reopen_advisory(advisory, by=setup["member"])
    advisory.refresh_from_db()
    assert advisory.assigned_cve_id == ""
    assert OrphanCve.objects.filter(previous_advisory=advisory).count() == 0
    assert OrphanCveReassignmentTask.objects.filter(advisory=advisory).count() == 0


# ---------------------- View integration -----------------------------------


@pytest.mark.django_db
def test_advisory_reopen_view(setup, client):
    advisory = _dismiss_draft(setup)
    client.force_login(setup["member"])
    url = reverse("advisories:reopen", args=[advisory.advisory_id])
    response = client.post(url)
    assert response.status_code == 302
    advisory.refresh_from_db()
    assert advisory.state == State.DRAFT


@pytest.mark.django_db
def test_advisory_reopen_view_blocks_outsider(setup, client):
    advisory = _dismiss_draft(setup)
    client.force_login(setup["outsider"])
    url = reverse("advisories:reopen", args=[advisory.advisory_id])
    response = client.post(url)
    assert response.status_code == 403
    advisory.refresh_from_db()
    assert advisory.state == State.DISMISSED


@pytest.mark.django_db
def test_advisory_reopen_view_rejects_get(setup, client):
    advisory = _dismiss_draft(setup)
    client.force_login(setup["member"])
    url = reverse("advisories:reopen", args=[advisory.advisory_id])
    response = client.get(url)
    assert response.status_code == 405


# ---------------------- Dismiss-time review reset ---------------------------


@pytest.mark.django_db
def test_dismiss_resets_changes_requested_review_status(setup):
    """A draft in CHANGES_REQUESTED gets its review_status wiped on dismiss
    so reopen lands in a clean draft (no stale review badge)."""
    from advisories.models import ReviewStatus

    advisory = setup["advisory"]
    advisory.review_status = ReviewStatus.CHANGES_REQUESTED
    advisory.save(update_fields=["review_status"])

    _dismiss_draft(setup)
    advisory.refresh_from_db()
    assert advisory.review_status == ReviewStatus.NONE
    # And the audit row carries the dismiss-side metadata so the timeline
    # can distinguish from a user-initiated withdraw_review.
    audit = AuditLogEntry.objects.filter(action=Action.ADVISORY_REVIEW_WITHDRAWN).first()
    assert audit is not None
    assert audit.metadata["cancelled_on_dismiss"] is True


@pytest.mark.django_db
def test_dismiss_closes_open_review_task_when_submitted(setup):
    """SUBMITTED has an OPEN ReviewTask that must be closed as WITHDRAWN
    on dismiss, otherwise the admin queue carries a phantom review for a
    dismissed advisory."""
    from advisories.models import ReviewStatus
    from advisories.services import record_advisory_version
    from workflows.models import ReviewTaskStatus

    advisory = setup["advisory"]
    record_advisory_version(advisory, editor=setup["member"])
    task = wf.submit_for_review(advisory, by=setup["member"])
    advisory.refresh_from_db()
    assert advisory.review_status == ReviewStatus.SUBMITTED
    assert task.status == ReviewTaskStatus.OPEN

    _dismiss_draft(setup)
    advisory.refresh_from_db()
    task.refresh_from_db()
    assert advisory.review_status == ReviewStatus.NONE
    assert task.status == ReviewTaskStatus.WITHDRAWN
    assert task.decided_at is not None


@pytest.mark.django_db
def test_dismiss_resets_approved_review_status(setup):
    """Stale APPROVED would let the owner publish without re-review after
    reopen — must be wiped at dismiss."""
    from advisories.models import ReviewStatus

    advisory = setup["advisory"]
    advisory.review_status = ReviewStatus.APPROVED
    advisory.save(update_fields=["review_status"])

    _dismiss_draft(setup)
    advisory.refresh_from_db()
    assert advisory.review_status == ReviewStatus.NONE


@pytest.mark.django_db
def test_dismiss_with_none_review_status_writes_no_review_audit(setup):
    """Control: a never-reviewed draft dismissed cleanly should not emit
    an ADVISORY_REVIEW_WITHDRAWN row."""
    _dismiss_draft(setup)
    assert not AuditLogEntry.objects.filter(action=Action.ADVISORY_REVIEW_WITHDRAWN).exists()


@pytest.mark.django_db
def test_reopen_after_changes_requested_lands_in_clean_draft(setup):
    """End-to-end: CHANGES_REQUESTED → dismiss → reopen should leave the
    advisory in draft with no pending review state at all."""
    from advisories.models import ReviewStatus

    advisory = setup["advisory"]
    advisory.review_status = ReviewStatus.CHANGES_REQUESTED
    advisory.save(update_fields=["review_status"])

    _dismiss_draft(setup)
    services.reopen_advisory(advisory, by=setup["member"])
    advisory.refresh_from_db()
    assert advisory.state == State.DRAFT
    assert advisory.review_status == ReviewStatus.NONE
    # Owner can submit for review again from this clean state.
    assert perms.can_submit_for_review(setup["member"], advisory) is True
