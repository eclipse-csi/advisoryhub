from __future__ import annotations

import pytest
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from advisories.models import Advisory, ReviewStatus, State
from audit.models import Action, AuditLogEntry
from comments.models import AdvisoryComment
from workflows import services as wf
from workflows.models import (
    CveRequestStatus,
    CveRequestTask,
    ReviewTaskStatus,
)


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    outsider = make_user(email="o@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x", created_by=member)
    return {"admin": admin, "member": member, "outsider": outsider, "advisory": advisory}


# ---------------------------------------------------------------------------
# CVE workflow
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_request_cve_creates_task_and_audit(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    assert task.status == CveRequestStatus.QUEUED
    assert AuditLogEntry.objects.filter(action=Action.CVE_REQUESTED).exists()


@pytest.mark.django_db
def test_request_cve_blocked_for_outsider(setup):
    with pytest.raises(PermissionDenied):
        wf.request_cve(setup["advisory"], by=setup["outsider"])


@pytest.mark.django_db
def test_cve_transition_only_admin(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    with pytest.raises(PermissionDenied):
        wf.transition_cve_request(
            task,
            by=setup["member"],
            new_status=CveRequestStatus.RESERVED,
            cve_id="CVE-2026-1234",
        )


@pytest.mark.django_db
def test_queued_to_reserved_sets_assigned_cve_and_assignee(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task,
        by=setup["admin"],
        new_status=CveRequestStatus.RESERVED,
        cve_id="CVE-2026-1234",
    )
    task.refresh_from_db()
    assert task.status == CveRequestStatus.RESERVED
    assert task.cve_id == "CVE-2026-1234"
    assert task.finished_at is not None
    assert task.assignee == setup["admin"]
    setup["advisory"].refresh_from_db()
    # RESERVED writes the EF-assigned CVE to its own field; the editable
    # aliases list is untouched.
    assert setup["advisory"].assigned_cve_id == "CVE-2026-1234"
    assert setup["advisory"].aliases == []
    assert AuditLogEntry.objects.filter(action=Action.CVE_TASK_STATUS_CHANGED).exists()


@pytest.mark.django_db
def test_cve_reserve_requires_cve_id(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    with pytest.raises(ValueError):
        wf.transition_cve_request(task, by=setup["admin"], new_status=CveRequestStatus.RESERVED)


@pytest.mark.django_db
def test_cve_invalid_cve_id_format_rejected(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    from django.core.exceptions import ValidationError

    with pytest.raises(ValidationError):
        wf.transition_cve_request(
            task,
            by=setup["admin"],
            new_status=CveRequestStatus.RESERVED,
            cve_id="not-a-cve",
        )


@pytest.mark.django_db
def test_cve_transition_invalid_target_rejected(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task,
        by=setup["admin"],
        new_status=CveRequestStatus.RESERVED,
        cve_id="CVE-2026-1234",
    )
    # Reserved is terminal — no further transitions allowed.
    with pytest.raises(ValueError):
        wf.transition_cve_request(
            task,
            by=setup["admin"],
            new_status=CveRequestStatus.REJECTED,
            notes="changed my mind",
        )


@pytest.mark.django_db
def test_reserve_on_published_advisory_flags_republish_required(setup):
    """Reserving a CVE after publication must flag the advisory for re-publish:
    the on-disk OSV/CSAF reflect the pre-CVE snapshot."""
    advisory = setup["advisory"]
    advisory.state = State.PUBLISHED
    advisory.republish_required = False
    advisory.save(update_fields=["state", "republish_required"])
    task = wf.request_cve(advisory, by=setup["member"])
    wf.transition_cve_request(
        task,
        by=setup["admin"],
        new_status=CveRequestStatus.RESERVED,
        cve_id="CVE-2026-1234",
    )
    advisory.refresh_from_db()
    assert advisory.assigned_cve_id == "CVE-2026-1234"
    assert advisory.republish_required is True


@pytest.mark.django_db
def test_reserve_on_unpublished_advisory_does_not_set_republish_required(setup):
    """For a draft/triage advisory the flag stays false — there's nothing yet
    published to re-publish."""
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task,
        by=setup["admin"],
        new_status=CveRequestStatus.RESERVED,
        cve_id="CVE-2026-1234",
    )
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].republish_required is False


@pytest.mark.django_db
def test_cve_aliases_never_mutated_by_workflow(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task,
        by=setup["admin"],
        new_status=CveRequestStatus.REJECTED,
        notes="duplicate of an existing CVE",
    )
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].aliases == []
    assert setup["advisory"].assigned_cve_id == ""


# ---------------------------------------------------------------------------
# CVE request: one-open-at-a-time, ban, assigned guards
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_second_request_blocked_while_one_is_open(setup):
    wf.request_cve(setup["advisory"], by=setup["member"])
    with pytest.raises(PermissionDenied):
        wf.request_cve(setup["advisory"], by=setup["member"])


@pytest.mark.django_db
def test_unique_open_constraint_blocks_bypass_of_service_check(setup):
    """Defense in depth: the DB partial unique constraint must reject a second
    open task even if a caller bypasses the service-level check."""
    from django.db import IntegrityError, transaction

    wf.request_cve(setup["advisory"], by=setup["member"])
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            CveRequestTask.objects.create(advisory=setup["advisory"], requested_by=setup["member"])


@pytest.mark.django_db
def test_request_blocked_when_cve_already_assigned(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task,
        by=setup["admin"],
        new_status=CveRequestStatus.RESERVED,
        cve_id="CVE-2026-9999",
    )
    with pytest.raises(PermissionDenied):
        wf.request_cve(setup["advisory"], by=setup["member"])


@pytest.mark.django_db
def test_request_blocked_when_banned(setup):
    setup["advisory"].cve_requests_banned = True
    setup["advisory"].save(update_fields=["cve_requests_banned"])
    with pytest.raises(PermissionDenied):
        wf.request_cve(setup["advisory"], by=setup["member"])


@pytest.mark.django_db
def test_can_re_request_after_rejection_when_not_banned(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task,
        by=setup["admin"],
        new_status=CveRequestStatus.REJECTED,
        notes="needs more detail",
    )
    second = wf.request_cve(setup["advisory"], by=setup["member"])
    assert second.pk != task.pk
    assert second.status == CveRequestStatus.QUEUED


# ---------------------------------------------------------------------------
# CVE rejection: notes -> comment, optional ban
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_reject_without_notes_raises(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    with pytest.raises(ValueError):
        wf.transition_cve_request(task, by=setup["admin"], new_status=CveRequestStatus.REJECTED)
    with pytest.raises(ValueError):
        wf.transition_cve_request(
            task, by=setup["admin"], new_status=CveRequestStatus.REJECTED, notes="   "
        )


@pytest.mark.django_db
def test_reject_creates_comment_authored_by_admin(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task,
        by=setup["admin"],
        new_status=CveRequestStatus.REJECTED,
        notes="not enough evidence — please attach a reproducer",
    )
    comment = AdvisoryComment.objects.get(advisory=setup["advisory"])
    assert comment.author == setup["admin"]
    assert "reproducer" in comment.body


@pytest.mark.django_db
def test_reject_with_ban_sets_flag_and_audit(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task,
        by=setup["admin"],
        new_status=CveRequestStatus.REJECTED,
        notes="abuse — repeated frivolous requests",
        ban_future_requests=True,
    )
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].cve_requests_banned is True
    assert AuditLogEntry.objects.filter(action=Action.CVE_REQUEST_BANNED).exists()
    # And further requests are now blocked.
    with pytest.raises(PermissionDenied):
        wf.request_cve(setup["advisory"], by=setup["member"])


@pytest.mark.django_db
def test_ban_flag_rejected_outside_rejection_transition(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    with pytest.raises(ValueError):
        wf.transition_cve_request(
            task,
            by=setup["admin"],
            new_status=CveRequestStatus.RESERVED,
            cve_id="CVE-2026-1234",
            ban_future_requests=True,
        )


# ---------------------------------------------------------------------------
# CVE request cancellation (auto, on advisory dismissal)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_cancel_open_cve_request_transitions_and_audits(setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    result = wf.cancel_open_cve_request(
        setup["advisory"], by=setup["admin"], reason="Advisory dismissed: duplicate"
    )
    assert result is not None
    assert result.pk == task.pk
    task.refresh_from_db()
    assert task.status == CveRequestStatus.CANCELLED
    assert task.finished_at is not None
    assert task.notes == "Advisory dismissed: duplicate"
    assert AuditLogEntry.objects.filter(action=Action.CVE_REQUEST_CANCELLED).exists()
    # No public comment is created on auto-cancellation (unlike rejection).
    assert not AdvisoryComment.objects.filter(advisory=setup["advisory"]).exists()


@pytest.mark.django_db
def test_cancel_open_cve_request_noop_when_none_open(setup):
    result = wf.cancel_open_cve_request(
        setup["advisory"], by=setup["admin"], reason="nothing to cancel"
    )
    assert result is None
    assert not AuditLogEntry.objects.filter(action=Action.CVE_REQUEST_CANCELLED).exists()


@pytest.mark.django_db
def test_cancelled_does_not_block_fresh_request(setup):
    wf.request_cve(setup["advisory"], by=setup["member"])
    wf.cancel_open_cve_request(setup["advisory"], by=setup["admin"], reason="dismissed")
    # The cancelled task is terminal; a brand-new request is allowed.
    fresh = wf.request_cve(setup["advisory"], by=setup["member"])
    assert fresh.status == CveRequestStatus.QUEUED


# ---------------------------------------------------------------------------
# Orphan CVE workflow: unassign + mark-rejected-at-cve.org
# ---------------------------------------------------------------------------


def _reserve_cve(setup, cve_id="CVE-2026-1234"):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task, by=setup["admin"], new_status=CveRequestStatus.RESERVED, cve_id=cve_id
    )
    setup["advisory"].refresh_from_db()
    return task


@pytest.mark.django_db
def test_unassign_cve_clears_field_and_creates_orphan(setup):
    from workflows.models import OrphanCve, OrphanCveStatus

    _reserve_cve(setup)
    orphan = wf.unassign_cve(
        setup["advisory"], by=setup["admin"], reason="reserved against wrong advisory"
    )
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].assigned_cve_id == ""
    assert isinstance(orphan, OrphanCve)
    assert orphan.cve_id == "CVE-2026-1234"
    assert orphan.status == OrphanCveStatus.ORPHANED
    assert orphan.unassigned_by == setup["admin"]
    assert orphan.unassign_reason == "reserved against wrong advisory"
    assert orphan.previous_advisory == setup["advisory"]
    assert orphan.previous_advisory_label == setup["advisory"].advisory_id
    assert AuditLogEntry.objects.filter(action=Action.CVE_UNASSIGNED).exists()


@pytest.mark.django_db
def test_unassign_on_published_advisory_flags_republish_required(setup):
    """Removing an EF-assigned CVE on a published advisory leaves the on-disk
    OSV/CSAF carrying the now-orphaned id — flag for re-publish."""
    _reserve_cve(setup)
    advisory = setup["advisory"]
    advisory.state = State.PUBLISHED
    advisory.republish_required = False
    advisory.save(update_fields=["state", "republish_required"])
    wf.unassign_cve(advisory, by=setup["admin"], reason="reserved against wrong advisory")
    advisory.refresh_from_db()
    assert advisory.assigned_cve_id == ""
    assert advisory.republish_required is True


@pytest.mark.django_db
def test_unassign_cve_blocked_for_non_admin(setup):
    _reserve_cve(setup)
    with pytest.raises(PermissionDenied):
        wf.unassign_cve(setup["advisory"], by=setup["member"], reason="x")
    with pytest.raises(PermissionDenied):
        wf.unassign_cve(setup["advisory"], by=setup["outsider"], reason="x")


@pytest.mark.django_db
def test_unassign_cve_blocked_when_nothing_assigned(setup):
    with pytest.raises(ValueError):
        wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="x")


@pytest.mark.django_db
def test_unassign_cve_requires_reason(setup):
    _reserve_cve(setup)
    with pytest.raises(ValueError):
        wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="")
    with pytest.raises(ValueError):
        wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="    ")


@pytest.mark.django_db
def test_can_re_request_cve_after_unassign(setup):
    _reserve_cve(setup)
    wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="redo")
    setup["advisory"].refresh_from_db()
    fresh = wf.request_cve(setup["advisory"], by=setup["member"])
    assert fresh.status == CveRequestStatus.QUEUED


@pytest.mark.django_db
def test_orphan_cve_id_is_unique(setup):
    from django.db import IntegrityError, transaction

    from workflows.models import OrphanCve

    _reserve_cve(setup)
    wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="redo")
    # A second OrphanCve with the same cve_id must be rejected by the DB.
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            OrphanCve.objects.create(
                cve_id="CVE-2026-1234",
                unassigned_by=setup["admin"],
                unassign_reason="dup",
            )


@pytest.mark.django_db
def test_mark_orphan_rejected_happy_path(setup):
    from workflows.models import OrphanCveStatus

    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="redo")
    wf.mark_orphan_rejected(orphan, by=setup["admin"], notes="MITRE ticket #abc")
    orphan.refresh_from_db()
    assert orphan.status == OrphanCveStatus.MARKED_REJECTED
    assert orphan.marked_rejected_by == setup["admin"]
    assert orphan.marked_rejected_at is not None
    assert orphan.marked_rejected_notes == "MITRE ticket #abc"
    assert AuditLogEntry.objects.filter(action=Action.CVE_MARKED_REJECTED_AT_CVE_ORG).exists()


@pytest.mark.django_db
def test_mark_orphan_rejected_blocked_for_non_admin(setup):
    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="redo")
    with pytest.raises(PermissionDenied):
        wf.mark_orphan_rejected(orphan, by=setup["member"])


@pytest.mark.django_db
def test_mark_orphan_rejected_blocked_when_already_marked(setup):
    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="redo")
    wf.mark_orphan_rejected(orphan, by=setup["admin"])
    with pytest.raises(PermissionDenied):
        wf.mark_orphan_rejected(orphan, by=setup["admin"])


# ---------------------------------------------------------------------------
# Review workflow
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_submit_for_review_pins_latest_version_and_opens_task(setup):
    advisory = setup["advisory"]
    expected_version = advisory.versions.order_by("-version").first()
    task = wf.submit_for_review(advisory, by=setup["member"])
    advisory.refresh_from_db()
    assert advisory.review_status == ReviewStatus.SUBMITTED
    assert advisory.submitted_for_review_by == setup["member"]
    assert task.status == ReviewTaskStatus.OPEN
    assert task.version == expected_version
    assert AuditLogEntry.objects.filter(action=Action.ADVISORY_SUBMITTED_FOR_REVIEW).exists()


@pytest.mark.django_db
def test_submit_blocked_for_outsider(setup):
    with pytest.raises(PermissionDenied):
        wf.submit_for_review(setup["advisory"], by=setup["outsider"])


@pytest.mark.django_db
def test_submit_blocked_for_admin(setup):
    """Admins are reviewers, not submitters."""
    with pytest.raises(PermissionDenied):
        wf.submit_for_review(setup["advisory"], by=setup["admin"])


@pytest.mark.django_db
def test_submit_blocked_when_already_in_review(setup):
    wf.submit_for_review(setup["advisory"], by=setup["member"])
    with pytest.raises(PermissionDenied):
        wf.submit_for_review(setup["advisory"], by=setup["member"])


@pytest.mark.django_db
def test_submitted_advisory_freezes_editing(client, setup):
    """Submitted advisory: editor view returns 403 for the project member."""
    advisory = setup["advisory"]
    wf.submit_for_review(advisory, by=setup["member"])
    client.force_login(setup["member"])
    response = client.get(reverse("advisories:edit", args=[advisory.advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_admin_can_still_edit_during_review(client, setup):
    advisory = setup["advisory"]
    wf.submit_for_review(advisory, by=setup["member"])
    client.force_login(setup["admin"])
    response = client.get(reverse("advisories:edit", args=[advisory.advisory_id]))
    assert response.status_code == 200


@pytest.mark.django_db
def test_review_approve_transitions(setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["member"])
    wf.approve_review(task, by=setup["admin"], notes="LGTM")
    task.refresh_from_db()
    setup["advisory"].refresh_from_db()
    assert task.status == ReviewTaskStatus.APPROVED
    assert setup["advisory"].review_status == ReviewStatus.APPROVED
    assert AuditLogEntry.objects.filter(action=Action.ADVISORY_REVIEW_APPROVED).exists()


@pytest.mark.django_db
def test_review_request_changes_then_reopen(setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["member"])
    wf.request_changes(task, by=setup["admin"], notes="please fix references")
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].review_status == ReviewStatus.CHANGES_REQUESTED

    # The original author can reopen
    wf.reopen_review(setup["advisory"], by=setup["member"])
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].review_status == ReviewStatus.NONE


@pytest.mark.django_db
def test_review_decision_blocked_for_non_admin(setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["member"])
    with pytest.raises(PermissionDenied):
        wf.approve_review(task, by=setup["member"], notes="self-approve")


@pytest.mark.django_db
def test_cannot_decide_already_decided_review(setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["member"])
    wf.approve_review(task, by=setup["admin"])
    with pytest.raises(PermissionDenied):
        wf.request_changes(task, by=setup["admin"])


@pytest.mark.django_db
def test_resubmission_pins_new_version_and_opens_new_task(setup):
    from advisories.services import record_advisory_version

    advisory = setup["advisory"]
    task1 = wf.submit_for_review(advisory, by=setup["member"])
    wf.request_changes(task1, by=setup["admin"], notes="fixme")
    wf.reopen_review(advisory, by=setup["member"])
    advisory.summary = "edited after feedback"
    advisory.save()
    # Simulate the edit flow appending the new version row.
    record_advisory_version(advisory, editor=setup["member"])

    task2 = wf.submit_for_review(advisory, by=setup["member"])
    assert task2.pk != task1.pk
    assert task2.version.pk != task1.version.pk
    # Original version still has the original content
    assert task1.version.payload["summary"] == "x"
    # New version has the edited content
    assert task2.version.payload["summary"] == "edited after feedback"


@pytest.mark.django_db
def test_reopen_blocked_when_not_in_changes_or_rejected(setup):
    advisory = setup["advisory"]
    with pytest.raises(PermissionDenied):
        wf.reopen_review(advisory, by=setup["member"])
    wf.submit_for_review(advisory, by=setup["member"])
    advisory.refresh_from_db()
    with pytest.raises(PermissionDenied):
        wf.reopen_review(advisory, by=setup["member"])


# ---------------------------------------------------------------------------
# Withdraw review
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_withdraw_review_sets_status_and_closes_task(setup):
    advisory = setup["advisory"]
    task = wf.submit_for_review(advisory, by=setup["member"])

    wf.withdraw_review(advisory, by=setup["member"])

    advisory.refresh_from_db()
    task.refresh_from_db()
    assert advisory.review_status == ReviewStatus.NONE
    assert task.status == ReviewTaskStatus.WITHDRAWN
    assert task.decided_at is not None
    assert AuditLogEntry.objects.filter(action=Action.ADVISORY_REVIEW_WITHDRAWN).exists()
    assert AuditLogEntry.objects.filter(
        action=Action.REVIEW_TASK_STATUS_CHANGED,
        new_value__status=ReviewTaskStatus.WITHDRAWN,
    ).exists()


@pytest.mark.django_db
def test_withdraw_review_rejected_when_not_submitted(setup):
    advisory = setup["advisory"]
    with pytest.raises(PermissionDenied):
        wf.withdraw_review(advisory, by=setup["member"])


@pytest.mark.django_db
def test_withdraw_review_blocked_for_outsider(setup):
    wf.submit_for_review(setup["advisory"], by=setup["member"])
    with pytest.raises(PermissionDenied):
        wf.withdraw_review(setup["advisory"], by=setup["outsider"])


@pytest.mark.django_db
def test_resubmit_after_withdraw(setup):
    advisory = setup["advisory"]
    task1 = wf.submit_for_review(advisory, by=setup["member"])
    wf.withdraw_review(advisory, by=setup["member"])
    advisory.refresh_from_db()

    task2 = wf.submit_for_review(advisory, by=setup["member"])
    assert task2.pk != task1.pk
    assert advisory.review_status == ReviewStatus.SUBMITTED


@pytest.mark.django_db
def test_admin_inbox_excludes_withdrawn_tasks(setup):
    """The admin queue surfaces only OPEN review tasks; a withdrawn one drops out."""
    from workflows.models import ReviewTask

    wf.submit_for_review(setup["advisory"], by=setup["member"])
    assert ReviewTask.objects.filter(status=ReviewTaskStatus.OPEN).count() == 1

    wf.withdraw_review(setup["advisory"], by=setup["member"])
    assert ReviewTask.objects.filter(status=ReviewTaskStatus.OPEN).count() == 0
    assert ReviewTask.objects.filter(status=ReviewTaskStatus.WITHDRAWN).count() == 1


@pytest.mark.django_db
def test_publish_blocked_while_submitted_for_review(setup):
    """End-to-end: submit → can't publish (even admin) → withdraw → drafts again."""
    from advisories import permissions as perms

    advisory = setup["advisory"]
    project = advisory.project
    project.is_mature_publisher = True
    project.save()

    # Before submission, mature-publisher owner can publish.
    assert perms.can_publish(setup["member"], advisory)

    wf.submit_for_review(advisory, by=setup["member"])
    advisory.refresh_from_db()
    # While SUBMITTED, neither admin nor mature-publisher owner can publish.
    assert not perms.can_publish(setup["admin"], advisory)
    assert not perms.can_publish(setup["member"], advisory)

    wf.withdraw_review(advisory, by=setup["member"])
    advisory.refresh_from_db()
    assert perms.can_publish(setup["member"], advisory)


# ---------------------------------------------------------------------------
# Revoke approval (manual admin action)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_revoke_approval_sets_status_and_audits(setup):
    advisory = setup["advisory"]
    advisory.review_status = ReviewStatus.APPROVED
    advisory.save()

    wf.revoke_approval(advisory, by=setup["admin"], reason="content drifted")

    advisory.refresh_from_db()
    assert advisory.review_status == ReviewStatus.NONE
    entry = AuditLogEntry.objects.filter(
        action=Action.ADVISORY_REVIEW_APPROVAL_REVOKED, advisory=advisory
    ).first()
    assert entry is not None
    assert entry.metadata == {"reason": "content drifted"}


@pytest.mark.django_db
def test_revoke_approval_blocked_when_not_approved(setup):
    advisory = setup["advisory"]
    # Default status is NONE.
    with pytest.raises(PermissionDenied):
        wf.revoke_approval(advisory, by=setup["admin"])


@pytest.mark.django_db
def test_revoke_approval_blocked_for_non_admin(setup):
    advisory = setup["advisory"]
    advisory.review_status = ReviewStatus.APPROVED
    advisory.save()
    with pytest.raises(PermissionDenied):
        wf.revoke_approval(advisory, by=setup["member"])


# ---------------------------------------------------------------------------
# Reopen support: reassign_orphan_cve + resolve_reassignment_task
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_reassign_orphan_cve_happy_path(setup):
    from workflows.models import OrphanCveStatus

    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="re-do")
    # Reset advisory.assigned_cve_id to mimic what reopen does (clear before
    # reassigning); unassign_cve already cleared it.
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].assigned_cve_id == ""

    wf.reassign_orphan_cve(orphan, by=setup["admin"], advisory=setup["advisory"])
    setup["advisory"].refresh_from_db()
    orphan.refresh_from_db()
    assert setup["advisory"].assigned_cve_id == "CVE-2026-1234"
    assert orphan.status == OrphanCveStatus.REASSIGNED
    assert AuditLogEntry.objects.filter(action=Action.CVE_REASSIGNED_FROM_ORPHAN).exists()


@pytest.mark.django_db
def test_reassign_orphan_cve_blocked_when_advisory_already_holds_cve(setup):
    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="re-do")
    # Force-assign a different CVE to the advisory; reassign should refuse
    # rather than silently overwrite.
    setup["advisory"].assigned_cve_id = "CVE-2026-5555"
    setup["advisory"].save(update_fields=["assigned_cve_id"])
    with pytest.raises(ValueError):
        wf.reassign_orphan_cve(orphan, by=setup["admin"], advisory=setup["advisory"])


@pytest.mark.django_db
def test_reassign_orphan_cve_blocked_when_cve_held_elsewhere(setup, make_user, make_project):
    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="re-do")
    other_project = make_project("beta")
    other_advisory = Advisory.objects.create(
        project=other_project,
        summary="other",
        assigned_cve_id=orphan.cve_id,
    )
    with pytest.raises(ValueError):
        wf.reassign_orphan_cve(orphan, by=setup["admin"], advisory=setup["advisory"])
    # And sanity-check: no audit row written when we refuse.
    assert not AuditLogEntry.objects.filter(action=Action.CVE_REASSIGNED_FROM_ORPHAN).exists()
    other_advisory.refresh_from_db()  # exists  # noqa: F841


@pytest.mark.django_db
def test_resolve_reassignment_task_requires_admin(setup):
    from workflows.models import OrphanCveReassignmentTask

    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="re-do")
    wf.mark_orphan_rejected(orphan, by=setup["admin"], notes="cve.org ticket")
    task = OrphanCveReassignmentTask.objects.create(
        orphan_cve=orphan,
        advisory=setup["advisory"],
        requested_by=setup["member"],
    )
    with pytest.raises(PermissionDenied):
        wf.resolve_reassignment_task(task, by=setup["member"], outcome="reassigned")


@pytest.mark.django_db
def test_resolve_reassignment_task_reassigned(setup):
    from workflows.models import (
        OrphanCveReassignmentStatus,
        OrphanCveReassignmentTask,
        OrphanCveStatus,
    )

    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="re-do")
    wf.mark_orphan_rejected(orphan, by=setup["admin"], notes="cve.org ticket")
    task = OrphanCveReassignmentTask.objects.create(
        orphan_cve=orphan,
        advisory=setup["advisory"],
        requested_by=setup["member"],
    )
    wf.resolve_reassignment_task(task, by=setup["admin"], outcome="reassigned")
    task.refresh_from_db()
    orphan.refresh_from_db()
    setup["advisory"].refresh_from_db()
    assert task.status == OrphanCveReassignmentStatus.RESOLVED_REASSIGNED
    assert orphan.status == OrphanCveStatus.REASSIGNED
    assert setup["advisory"].assigned_cve_id == "CVE-2026-1234"
    assert AuditLogEntry.objects.filter(action=Action.ORPHAN_REASSIGNMENT_RESOLVED).exists()


@pytest.mark.django_db
def test_resolve_reassignment_task_replaced_with_new_cve(setup):
    from workflows.models import (
        OrphanCveReassignmentStatus,
        OrphanCveReassignmentTask,
        OrphanCveStatus,
    )

    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="re-do")
    wf.mark_orphan_rejected(orphan, by=setup["admin"], notes="cve.org ticket")
    task = OrphanCveReassignmentTask.objects.create(
        orphan_cve=orphan,
        advisory=setup["advisory"],
        requested_by=setup["member"],
    )

    wf.resolve_reassignment_task(
        task,
        by=setup["admin"],
        outcome="replaced",
        replacement_cve_id="CVE-2026-7777",
        notes="cve.org wouldn't undo, took fresh id",
    )

    task.refresh_from_db()
    orphan.refresh_from_db()
    setup["advisory"].refresh_from_db()
    assert task.status == OrphanCveReassignmentStatus.RESOLVED_REPLACED
    assert task.replacement_cve_id == "CVE-2026-7777"
    # Orphan stays MARKED_REJECTED — it really is rejected at cve.org.
    assert orphan.status == OrphanCveStatus.MARKED_REJECTED
    assert setup["advisory"].assigned_cve_id == "CVE-2026-7777"
    # A fresh CveRequestTask exists in RESERVED for the new CVE so the
    # standard history surface still records the assignment.
    reserved = CveRequestTask.objects.filter(
        advisory=setup["advisory"], status=CveRequestStatus.RESERVED, cve_id="CVE-2026-7777"
    )
    assert reserved.count() == 1


@pytest.mark.django_db
def test_resolve_reassignment_task_replaced_requires_cve_id(setup):
    from workflows.models import OrphanCveReassignmentTask

    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="re-do")
    wf.mark_orphan_rejected(orphan, by=setup["admin"], notes="cve.org ticket")
    task = OrphanCveReassignmentTask.objects.create(
        orphan_cve=orphan,
        advisory=setup["advisory"],
        requested_by=setup["member"],
    )
    with pytest.raises(ValueError):
        wf.resolve_reassignment_task(
            task, by=setup["admin"], outcome="replaced", replacement_cve_id=""
        )


@pytest.mark.django_db
def test_resolve_reassignment_task_rejects_unknown_outcome(setup):
    from workflows.models import OrphanCveReassignmentTask

    _reserve_cve(setup)
    orphan = wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="re-do")
    task = OrphanCveReassignmentTask.objects.create(
        orphan_cve=orphan,
        advisory=setup["advisory"],
        requested_by=setup["member"],
    )
    with pytest.raises(ValueError):
        wf.resolve_reassignment_task(task, by=setup["admin"], outcome="something")


# ---------------------------------------------------------------------------
# cancel_pending_review (dismiss-time teardown of pending review state)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_cancel_pending_review_noop_when_none(setup):
    """No review state → no audit row, returns None."""
    result = wf.cancel_pending_review(setup["advisory"], by=setup["admin"], reason="dismissed")
    assert result is None
    assert not AuditLogEntry.objects.filter(action=Action.ADVISORY_REVIEW_WITHDRAWN).exists()


@pytest.mark.django_db
def test_cancel_pending_review_resets_changes_requested(setup):
    """CHANGES_REQUESTED has no OPEN task (the prior task is terminal); only
    the review_status field needs resetting."""
    advisory = setup["advisory"]
    advisory.review_status = ReviewStatus.CHANGES_REQUESTED
    advisory.save(update_fields=["review_status"])

    result = wf.cancel_pending_review(advisory, by=setup["admin"], reason="dismissed")
    advisory.refresh_from_db()
    assert result is None  # No open task to close.
    assert advisory.review_status == ReviewStatus.NONE
    audit = AuditLogEntry.objects.filter(action=Action.ADVISORY_REVIEW_WITHDRAWN).first()
    assert audit is not None
    assert audit.metadata["cancelled_on_dismiss"] is True
    assert audit.previous_value == {"review_status": ReviewStatus.CHANGES_REQUESTED.value}


@pytest.mark.django_db
def test_cancel_pending_review_closes_submitted_open_task(setup):
    """SUBMITTED has an OPEN ReviewTask that must be withdrawn."""
    advisory = setup["advisory"]
    # Seed v1 so submit_for_review can pin a version.
    from advisories.services import record_advisory_version

    record_advisory_version(advisory, editor=setup["member"])
    task = wf.submit_for_review(advisory, by=setup["member"])
    advisory.refresh_from_db()
    assert advisory.review_status == ReviewStatus.SUBMITTED
    assert task.status == ReviewTaskStatus.OPEN

    closed = wf.cancel_pending_review(advisory, by=setup["admin"], reason="dismissed")
    advisory.refresh_from_db()
    task.refresh_from_db()
    assert closed is not None
    assert closed.pk == task.pk
    assert task.status == ReviewTaskStatus.WITHDRAWN
    assert task.decided_at is not None
    assert advisory.review_status == ReviewStatus.NONE
    assert AuditLogEntry.objects.filter(action=Action.ADVISORY_REVIEW_WITHDRAWN).exists()
    assert AuditLogEntry.objects.filter(action=Action.REVIEW_TASK_STATUS_CHANGED).exists()


@pytest.mark.django_db
def test_cancel_pending_review_resets_approved(setup):
    """APPROVED is the security-relevant case — a surviving approval would
    let the owner publish without re-review after reopen."""
    advisory = setup["advisory"]
    advisory.review_status = ReviewStatus.APPROVED
    advisory.save(update_fields=["review_status"])

    wf.cancel_pending_review(advisory, by=setup["admin"], reason="dismissed")
    advisory.refresh_from_db()
    assert advisory.review_status == ReviewStatus.NONE
