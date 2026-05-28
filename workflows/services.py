"""State-transition helpers for CVE and review tasks.

Always go through these helpers — they enforce allowed transitions, stamp
timestamps, append to the audit log, and queue notification emails.
"""

from __future__ import annotations

from functools import partial

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from advisories import permissions as perms
from advisories import services as advisory_services
from advisories.models import Advisory, Kind, ReviewStatus, State
from audit.models import Action
from audit.services import record
from comments.services import add_comment
from common.enqueue import safe_enqueue
from common.users import actor_or_none

from .models import (
    CveRequestStatus,
    CveRequestTask,
    OrphanCve,
    OrphanCveReassignmentStatus,
    OrphanCveReassignmentTask,
    OrphanCveStatus,
    ReviewTask,
    ReviewTaskStatus,
)

# ---------------------------------------------------------------------------
# CVE request workflow
# ---------------------------------------------------------------------------


@transaction.atomic
def request_cve(advisory: Advisory, *, by) -> CveRequestTask:
    if not perms.can_edit(by, advisory):
        raise PermissionDenied("You cannot request a CVE for this advisory.")
    if advisory.cve_requests_banned:
        raise PermissionDenied("CVE requests are disabled for this advisory.")
    if advisory.assigned_cve_id:
        raise PermissionDenied(
            f"This advisory already has an assigned CVE ({advisory.assigned_cve_id})."
        )
    if advisory.cve_requests.filter(status=CveRequestStatus.QUEUED).exists():
        raise PermissionDenied("A CVE request is already pending for this advisory.")
    task = CveRequestTask.objects.create(advisory=advisory, requested_by=by)
    record(
        action=Action.CVE_REQUESTED,
        actor=by,
        advisory=advisory,
        new_value={"task_id": task.pk, "status": task.status},
    )
    return task


@transaction.atomic
def transition_cve_request(
    task: CveRequestTask,
    *,
    by,
    new_status: str,
    cve_id: str | None = None,
    notes: str | None = None,
    ban_future_requests: bool = False,
) -> CveRequestTask:
    if not perms.can_review(by):
        raise PermissionDenied("Only the global admin/security group can transition CVE tasks.")
    if new_status not in CveRequestStatus.values:
        raise ValueError(f"Unknown CVE status {new_status!r}")
    if not _is_valid_cve_transition(task.status, new_status):
        raise ValueError(f"Cannot transition from {task.status} to {new_status}")
    if new_status == CveRequestStatus.RESERVED and not cve_id:
        raise ValueError("cve_id is required when reserving a CVE")
    if new_status == CveRequestStatus.REJECTED and not (notes or "").strip():
        # The rejection reason is mandatory because it becomes a public comment
        # on the advisory.
        raise ValueError("notes are required when rejecting a CVE request")
    if ban_future_requests and new_status != CveRequestStatus.REJECTED:
        raise ValueError("ban_future_requests is only valid when rejecting a CVE request")

    previous_status = task.status
    previous_cve_id = task.cve_id
    task.status = new_status
    if cve_id is not None:
        task.cve_id = cve_id
    if notes is not None:
        task.notes = notes
    if new_status in (CveRequestStatus.RESERVED, CveRequestStatus.REJECTED):
        task.assignee = actor_or_none(by)
        task.finished_at = timezone.now()
    task.full_clean(exclude=None)
    task.save()

    advisory = task.advisory
    if new_status == CveRequestStatus.RESERVED and cve_id:
        # The EF-assigned CVE is a first-class field on the advisory, not part
        # of the editable ``aliases`` list. OSV/CSAF builders merge it into the
        # output alias set at serialization time.
        advisory.assigned_cve_id = cve_id
        # If the advisory is already published, the on-disk OSV/CSAF reflect
        # the pre-CVE snapshot — flag for re-publication so the dashboard
        # surfaces it and the next push includes the assigned CVE.
        fields = ["assigned_cve_id", "modified_at"]
        if advisory.state == State.PUBLISHED and not advisory.republish_required:
            advisory.republish_required = True
            fields.append("republish_required")
        advisory.save(update_fields=fields)
        # For GHSA-linked advisories, fan out the EF-assigned CVE id to
        # the linked GHSA on GitHub. The push runs asynchronously so the
        # request handler returns immediately; failure of the push does
        # NOT roll back ``assigned_cve_id`` — the EF allocation stands.
        if advisory.kind == Kind.GHSA_LINKED:
            # Imported lazily to avoid a workflows ↔ ghsa import cycle at
            # module-load time.
            from ghsa import services as ghsa_services
            from ghsa.tasks import run_cve_push

            push_task = ghsa_services.enqueue_cve_push(advisory, cve_id, by=by)
            transaction.on_commit(partial(_enqueue_cve_push, push_task.pk, run_cve_push))

    if new_status == CveRequestStatus.REJECTED:
        # ``notes`` is validated non-empty for REJECTED above; ``or ""`` only
        # satisfies the str-typed ``body`` parameter.
        add_comment(advisory, author=by, body=notes or "")
        if ban_future_requests and not advisory.cve_requests_banned:
            advisory.cve_requests_banned = True
            advisory.save(update_fields=["cve_requests_banned", "modified_at"])
            record(
                action=Action.CVE_REQUEST_BANNED,
                actor=by,
                advisory=advisory,
                previous_value={"cve_requests_banned": False},
                new_value={"cve_requests_banned": True},
                metadata={"task_id": task.pk},
            )

    record(
        action=Action.CVE_TASK_STATUS_CHANGED,
        actor=by,
        advisory=advisory,
        previous_value={"status": previous_status, "cve_id": previous_cve_id},
        new_value={"status": new_status, "cve_id": task.cve_id},
        metadata={"task_id": task.pk},
    )
    return task


_CVE_TRANSITIONS: dict[str, set[str]] = {
    CveRequestStatus.QUEUED: {
        CveRequestStatus.RESERVED,
        CveRequestStatus.REJECTED,
        CveRequestStatus.CANCELLED,
    },
    CveRequestStatus.RESERVED: set(),
    CveRequestStatus.REJECTED: set(),
    CveRequestStatus.CANCELLED: set(),
}


def _is_valid_cve_transition(current: str, target: str) -> bool:
    return target in _CVE_TRANSITIONS.get(current, set())


@transaction.atomic
def cancel_open_cve_request(advisory: Advisory, *, by, reason: str) -> CveRequestTask | None:
    """Auto-cancel an open CVE request when its advisory is dismissed.

    Not gated by ``can_review`` — the caller (advisory dismissal) has already
    authorized this side-effect. ``reason`` is server-generated text from the
    dismissal flow, never user free-form input that could leak secrets.
    Returns the cancelled task, or ``None`` if no open request existed.
    """
    task = advisory.cve_requests.filter(status=CveRequestStatus.QUEUED).first()
    if task is None:
        return None
    previous_status = task.status
    task.status = CveRequestStatus.CANCELLED
    task.notes = reason or ""
    task.finished_at = timezone.now()
    task.save(update_fields=["status", "notes", "finished_at"])
    record(
        action=Action.CVE_REQUEST_CANCELLED,
        actor=by,
        advisory=advisory,
        previous_value={"status": previous_status},
        new_value={"status": CveRequestStatus.CANCELLED.value},
        metadata={"task_id": task.pk},
    )
    return task


@transaction.atomic
def cancel_pending_review(advisory: Advisory, *, by, reason: str) -> ReviewTask | None:
    """Tear down pending review state when an advisory is dismissed.

    Symmetric with :func:`cancel_open_cve_request`: not gated by
    ``can_review`` because the caller (advisory dismissal) has already
    authorized this side-effect. Without this, a dismiss/reopen cycle
    would leave the advisory carrying a stale ``review_status`` and (when
    previously ``SUBMITTED``) an ``OPEN`` :class:`ReviewTask` dangling on
    the admin queue. The ``APPROVED`` case is the most security-relevant:
    a stale approval surviving the cycle would let the owner publish
    without re-review on the way back out.

    Behaviour:

    * No-op when ``review_status == NONE`` — returns ``None``.
    * Otherwise: resets ``advisory.review_status`` to ``NONE``, closes any
      ``OPEN`` :class:`ReviewTask` as ``WITHDRAWN``, and audits.

    Returns the closed task or ``None`` (no open task existed, but the
    ``review_status`` may still have been reset from
    ``CHANGES_REQUESTED`` / ``APPROVED``).
    """
    if advisory.review_status == ReviewStatus.NONE:
        return None

    previous_review_status = advisory.review_status
    advisory.review_status = ReviewStatus.NONE
    advisory.save(update_fields=["review_status", "modified_at"])

    task = advisory.review_tasks.filter(status=ReviewTaskStatus.OPEN).first()
    if task is not None:
        task.status = ReviewTaskStatus.WITHDRAWN
        task.decided_at = timezone.now()
        task.save(update_fields=["status", "decided_at"])

    record(
        action=Action.ADVISORY_REVIEW_WITHDRAWN,
        actor=by,
        advisory=advisory,
        previous_value={"review_status": previous_review_status},
        new_value={"review_status": ReviewStatus.NONE.value},
        metadata={
            "cancelled_on_dismiss": True,
            "reason_length": len(reason or ""),
            "task_id": task.pk if task is not None else None,
        },
    )
    if task is not None:
        record(
            action=Action.REVIEW_TASK_STATUS_CHANGED,
            actor=by,
            advisory=advisory,
            previous_value={"status": ReviewTaskStatus.OPEN.value},
            new_value={"status": ReviewTaskStatus.WITHDRAWN.value, "task_id": task.pk},
        )
    return task


# ---------------------------------------------------------------------------
# Orphan CVE workflow (admin removes a reserved CVE; later records the
# out-of-band cve.org rejection)
# ---------------------------------------------------------------------------


@transaction.atomic
def unassign_cve(advisory: Advisory, *, by, reason: str) -> OrphanCve:
    """Admin removes the EF-assigned CVE from an advisory.

    Clears ``Advisory.assigned_cve_id`` and creates an ``OrphanCve`` row that
    surfaces in the dashboard queue until the admin records the cve.org
    rejection via ``mark_orphan_rejected``.
    """
    if not perms.can_unassign_cve(by, advisory):
        raise PermissionDenied("Only admins can unassign CVEs.")
    if not advisory.assigned_cve_id:
        raise ValueError("This advisory has no assigned CVE to remove.")
    if not (reason or "").strip():
        raise ValueError("A reason is required when unassigning a CVE.")

    previous_cve = advisory.assigned_cve_id
    orphan = OrphanCve.objects.create(
        cve_id=previous_cve,
        previous_advisory=advisory,
        previous_advisory_label=advisory.advisory_id,
        unassigned_by=actor_or_none(by),
        unassign_reason=reason,
    )
    advisory.assigned_cve_id = ""
    # Mirror update_cve_status: removing the CVE on a published advisory
    # means the on-disk OSV/CSAF still carry the now-orphaned id, so flag
    # for re-publication.
    fields = ["assigned_cve_id", "modified_at"]
    if advisory.state == State.PUBLISHED and not advisory.republish_required:
        advisory.republish_required = True
        fields.append("republish_required")
    advisory.save(update_fields=fields)
    record(
        action=Action.CVE_UNASSIGNED,
        actor=by,
        advisory=advisory,
        previous_value={"assigned_cve_id": previous_cve},
        new_value={"assigned_cve_id": "", "orphan_id": orphan.pk},
        metadata={"reason_length": len(reason)},
    )
    return orphan


@transaction.atomic
def reassign_orphan_cve(orphan: OrphanCve, *, by, advisory: Advisory) -> OrphanCve:
    """Reattach an orphaned CVE to its original advisory.

    Used by the reopen flow when an orphan is still in ``ORPHANED`` status
    (rejection wasn't yet pushed to cve.org) and also by
    :func:`resolve_reassignment_task` when an admin confirms a cve.org
    rejection was undone. The orphan transitions to ``REASSIGNED``;
    ``Advisory.assigned_cve_id`` is set back to the orphan's ``cve_id``.

    Guards:

    * The orphan must currently belong to ``advisory`` (no cross-advisory
      reassignment — the orphan row is the receipt for the original
      assignment).
    * The advisory must not currently hold an ``assigned_cve_id`` (reopen
      ran before this and cleared/never-restored it).
    * No other advisory may currently hold ``orphan.cve_id`` — that would
      double-assign the CVE.
    """
    if orphan.previous_advisory_id != advisory.pk:
        raise ValueError("Orphan CVE belongs to a different advisory.")
    if orphan.status not in (OrphanCveStatus.ORPHANED, OrphanCveStatus.MARKED_REJECTED):
        raise ValueError(f"Cannot reassign orphan in status {orphan.status} — already terminal.")
    if advisory.assigned_cve_id:
        raise ValueError(
            f"Advisory already holds {advisory.assigned_cve_id}; remove it before reassigning."
        )
    conflict = (
        Advisory.objects.filter(assigned_cve_id=orphan.cve_id).exclude(pk=advisory.pk).exists()
    )
    if conflict:
        raise ValueError(
            f"CVE {orphan.cve_id} is currently assigned to another advisory; cannot reassign."
        )

    previous_status = orphan.status
    orphan.status = OrphanCveStatus.REASSIGNED
    orphan.save(update_fields=["status"])

    advisory.assigned_cve_id = orphan.cve_id
    fields = ["assigned_cve_id", "modified_at"]
    advisory.save(update_fields=fields)

    record(
        action=Action.CVE_REASSIGNED_FROM_ORPHAN,
        actor=by,
        advisory=advisory,
        previous_value={"assigned_cve_id": "", "orphan_status": previous_status},
        new_value={
            "assigned_cve_id": orphan.cve_id,
            "orphan_status": OrphanCveStatus.REASSIGNED.value,
        },
        metadata={"orphan_id": orphan.pk},
    )
    return orphan


@transaction.atomic
def resolve_reassignment_task(
    task: OrphanCveReassignmentTask,
    *,
    by,
    outcome: str,
    replacement_cve_id: str = "",
    notes: str = "",
) -> OrphanCveReassignmentTask:
    """Admin resolves an :class:`OrphanCveReassignmentTask`.

    ``outcome`` is one of:

    * ``"reassigned"`` — the cve.org rejection was undone out-of-band. The
      orphan transitions to ``REASSIGNED`` and the CVE id is reattached to
      the advisory via :func:`reassign_orphan_cve`.
    * ``"replaced"`` — the rejection couldn't be undone. The admin enters a
      fresh ``replacement_cve_id`` on the form; a :class:`CveRequestTask`
      is created in ``RESERVED`` state for the new id, mirroring the path
      ``transition_cve_request`` takes when it reserves a CVE. The orphan
      itself stays ``marked_rejected``.

    Both outcomes are terminal for the task.
    """
    if not perms.can_manage_orphan_cves(by):
        raise PermissionDenied("Only admins can resolve orphan reassignment tasks.")
    if task.status != OrphanCveReassignmentStatus.QUEUED:
        raise PermissionDenied("This reassignment task has already been resolved.")

    clean_notes = (notes or "").strip()

    if outcome == "reassigned":
        reassign_orphan_cve(task.orphan_cve, by=by, advisory=task.advisory)
        task.status = OrphanCveReassignmentStatus.RESOLVED_REASSIGNED
    elif outcome == "replaced":
        clean_cve = (replacement_cve_id or "").strip()
        if not clean_cve:
            raise ValueError("A replacement CVE id is required to resolve as replaced.")
        from advisories.validators import validate_cve_id as _validate_cve_id

        _validate_cve_id(clean_cve)
        advisory = task.advisory
        if advisory.assigned_cve_id:
            raise ValueError(
                f"Advisory already holds {advisory.assigned_cve_id}; "
                "remove it before assigning a replacement."
            )
        conflict = (
            Advisory.objects.filter(assigned_cve_id=clean_cve).exclude(pk=advisory.pk).exists()
        )
        if conflict:
            raise ValueError(f"CVE {clean_cve} is currently assigned to another advisory.")
        reserved_task = CveRequestTask.objects.create(
            advisory=advisory,
            status=CveRequestStatus.RESERVED,
            requested_by=task.requested_by,
            assignee=actor_or_none(by),
            cve_id=clean_cve,
            notes=clean_notes,
            finished_at=timezone.now(),
        )
        advisory.assigned_cve_id = clean_cve
        advisory.save(update_fields=["assigned_cve_id", "modified_at"])
        task.replacement_cve_id = clean_cve
        task.status = OrphanCveReassignmentStatus.RESOLVED_REPLACED
        record(
            action=Action.CVE_TASK_STATUS_CHANGED,
            actor=by,
            advisory=advisory,
            previous_value={"status": "", "cve_id": ""},
            new_value={"status": CveRequestStatus.RESERVED.value, "cve_id": clean_cve},
            metadata={"task_id": reserved_task.pk, "from_reassignment_task_id": task.pk},
        )
    else:
        raise ValueError(f"Unknown outcome {outcome!r}; expected 'reassigned' or 'replaced'.")

    task.resolved_by = actor_or_none(by)
    task.resolution_notes = clean_notes
    task.finished_at = timezone.now()
    task.save(
        update_fields=[
            "status",
            "resolved_by",
            "replacement_cve_id",
            "resolution_notes",
            "finished_at",
        ]
    )
    record(
        action=Action.ORPHAN_REASSIGNMENT_RESOLVED,
        actor=by,
        advisory=task.advisory,
        previous_value={"status": OrphanCveReassignmentStatus.QUEUED.value},
        new_value={"status": task.status, "replacement_cve_id": task.replacement_cve_id},
        metadata={"task_id": task.pk, "orphan_id": task.orphan_cve_id},
    )
    return task


@transaction.atomic
def mark_orphan_rejected(orphan: OrphanCve, *, by, notes: str = "") -> OrphanCve:
    """Admin records that the orphan CVE was marked rejected at cve.org."""
    if not perms.can_manage_orphan_cves(by):
        raise PermissionDenied("Only admins can mark orphan CVEs rejected.")
    if orphan.status != OrphanCveStatus.ORPHANED:
        raise PermissionDenied("This orphan CVE has already been marked rejected.")

    orphan.status = OrphanCveStatus.MARKED_REJECTED
    orphan.marked_rejected_by = actor_or_none(by)
    orphan.marked_rejected_at = timezone.now()
    orphan.marked_rejected_notes = notes or ""
    orphan.save(
        update_fields=[
            "status",
            "marked_rejected_by",
            "marked_rejected_at",
            "marked_rejected_notes",
        ]
    )
    record(
        action=Action.CVE_MARKED_REJECTED_AT_CVE_ORG,
        actor=by,
        advisory=orphan.previous_advisory,
        previous_value={"status": OrphanCveStatus.ORPHANED.value},
        new_value={"status": OrphanCveStatus.MARKED_REJECTED.value, "orphan_id": orphan.pk},
    )
    return orphan


# ---------------------------------------------------------------------------
# Review workflow
# ---------------------------------------------------------------------------


@transaction.atomic
def submit_for_review(advisory: Advisory, *, by) -> ReviewTask:
    """Pin the current advisory version into a ReviewTask for the reviewer."""
    if not perms.can_submit_for_review(by, advisory):
        raise PermissionDenied("You cannot submit this advisory for review.")
    if advisory.state != State.DRAFT:
        raise PermissionDenied("Only draft advisories can be submitted for review.")
    if advisory.review_status == ReviewStatus.SUBMITTED:
        raise PermissionDenied("This advisory is already in review.")

    version = advisory_services.latest_version(advisory)
    if version is None:
        raise PermissionDenied("Advisory has no recorded version to submit for review.")
    advisory.review_status = ReviewStatus.SUBMITTED
    advisory.submitted_for_review_at = timezone.now()
    advisory.submitted_for_review_by = by
    advisory.save(
        update_fields=[
            "review_status",
            "submitted_for_review_at",
            "submitted_for_review_by",
            "modified_at",
        ]
    )

    task = ReviewTask.objects.create(advisory=advisory, version=version, submitted_by=by)
    record(
        action=Action.ADVISORY_SUBMITTED_FOR_REVIEW,
        actor=by,
        advisory=advisory,
        new_value={"version_id": version.pk, "version": version.version, "task_id": task.pk},
    )

    transaction.on_commit(lambda: _queue_event(advisory.pk, "advisory_submitted_for_review"))
    return task


@transaction.atomic
def approve_review(task: ReviewTask, *, by, notes: str = "") -> ReviewTask:
    return _decide_review(task, by=by, decision=ReviewTaskStatus.APPROVED, notes=notes)


@transaction.atomic
def request_changes(task: ReviewTask, *, by, notes: str = "") -> ReviewTask:
    return _decide_review(task, by=by, decision=ReviewTaskStatus.CHANGES_REQUESTED, notes=notes)


def _decide_review(task: ReviewTask, *, by, decision: ReviewTaskStatus, notes: str) -> ReviewTask:
    if not perms.can_review(by):
        raise PermissionDenied("Only the global admin/security group can decide reviews.")
    if task.status != ReviewTaskStatus.OPEN:
        raise PermissionDenied("This review task has already been decided.")

    advisory = task.advisory
    previous_status = advisory.review_status
    task.status = decision
    task.reviewer = by
    task.decision_notes = notes
    task.decided_at = timezone.now()
    task.save(update_fields=["status", "reviewer", "decision_notes", "decided_at"])

    new_review_status = {
        ReviewTaskStatus.APPROVED: ReviewStatus.APPROVED,
        ReviewTaskStatus.CHANGES_REQUESTED: ReviewStatus.CHANGES_REQUESTED,
    }[decision]
    advisory.review_status = new_review_status
    advisory.save(update_fields=["review_status", "modified_at"])

    audit_action = {
        ReviewTaskStatus.APPROVED: Action.ADVISORY_REVIEW_APPROVED,
        ReviewTaskStatus.CHANGES_REQUESTED: Action.ADVISORY_REVIEW_CHANGES_REQUESTED,
    }[decision]
    record(
        action=audit_action,
        actor=by,
        advisory=advisory,
        previous_value={"review_status": previous_status},
        new_value={"review_status": new_review_status, "task_id": task.pk},
    )
    record(
        action=Action.REVIEW_TASK_STATUS_CHANGED,
        actor=by,
        advisory=advisory,
        previous_value={"status": ReviewTaskStatus.OPEN},
        new_value={"status": decision, "task_id": task.pk},
    )
    return task


@transaction.atomic
def reopen_review(advisory: Advisory, *, by) -> Advisory:
    """Move a ``changes_requested`` advisory back to draft authoring.

    Available to the user who can edit the advisory; clears review_status to
    ``none`` so the project author can edit and re-submit.
    """
    # An admin or a member of the security team can reopen.
    if not (perms.is_global_admin(by) or perms.is_security_team_member(by, advisory.project)):
        raise PermissionDenied("You cannot reopen this review.")
    if advisory.review_status != ReviewStatus.CHANGES_REQUESTED:
        raise PermissionDenied("Review can only be reopened from changes-requested.")
    previous = advisory.review_status
    advisory.review_status = ReviewStatus.NONE
    advisory.save(update_fields=["review_status", "modified_at"])
    record(
        action=Action.ADVISORY_STATE_CHANGED,
        actor=by,
        advisory=advisory,
        previous_value={"review_status": previous},
        new_value={"review_status": ReviewStatus.NONE},
        metadata={"reopened": True},
    )
    return advisory


@transaction.atomic
def revoke_approval(advisory: Advisory, *, by, reason: str = "") -> Advisory:
    """Manually clear an APPROVED review_status (admin only).

    Edit-driven invalidation lives inline in ``advisory_edit``; this is
    the explicit admin action. End state matches: ``review_status`` drops
    to ``NONE`` and the next publish (for a non-mature project) requires
    a fresh submission and approval.
    """
    if not perms.can_revoke_approval(by, advisory):
        raise PermissionDenied("You cannot revoke this approval.")
    if advisory.review_status != ReviewStatus.APPROVED:
        raise PermissionDenied("Only an APPROVED advisory can have its approval revoked.")

    previous = advisory.review_status
    advisory.review_status = ReviewStatus.NONE
    advisory.save(update_fields=["review_status", "modified_at"])

    record(
        action=Action.ADVISORY_REVIEW_APPROVAL_REVOKED,
        actor=by,
        advisory=advisory,
        previous_value={"review_status": previous},
        new_value={"review_status": ReviewStatus.NONE},
        metadata={"reason": reason} if reason else None,
    )
    return advisory


@transaction.atomic
def withdraw_review(advisory: Advisory, *, by) -> Advisory:
    """Pull a pending review back to draft.

    Owners may cancel their own submission at any point before the admin
    has decided. The open ``ReviewTask`` closes as ``WITHDRAWN`` so the
    admin queue clears immediately; the snapshot taken at submission stays
    immutable. Withdrawing does *not* unlock publishing for non-mature
    projects — ``can_publish`` still requires an ``APPROVED`` review for
    them.
    """
    if not perms.can_withdraw_review(by, advisory):
        raise PermissionDenied("You cannot withdraw this review.")
    if advisory.review_status != ReviewStatus.SUBMITTED:
        raise PermissionDenied("Review can only be withdrawn while pending.")

    task = ReviewTask.objects.select_for_update().get(
        advisory=advisory, status=ReviewTaskStatus.OPEN
    )
    previous_review_status = advisory.review_status
    advisory.review_status = ReviewStatus.NONE
    advisory.save(update_fields=["review_status", "modified_at"])

    task.status = ReviewTaskStatus.WITHDRAWN
    task.decided_at = timezone.now()
    task.save(update_fields=["status", "decided_at"])

    record(
        action=Action.ADVISORY_REVIEW_WITHDRAWN,
        actor=by,
        advisory=advisory,
        previous_value={"review_status": previous_review_status},
        new_value={"review_status": ReviewStatus.NONE, "task_id": task.pk},
    )
    record(
        action=Action.REVIEW_TASK_STATUS_CHANGED,
        actor=by,
        advisory=advisory,
        previous_value={"status": ReviewTaskStatus.OPEN},
        new_value={"status": ReviewTaskStatus.WITHDRAWN, "task_id": task.pk},
    )

    transaction.on_commit(lambda: _queue_event(advisory.pk, "advisory_review_withdrawn"))
    return advisory


def _queue_event(advisory_id: int, event: str) -> None:
    from notifications.tasks import send_advisory_event_email

    safe_enqueue(send_advisory_event_email, advisory_id, event)


def _enqueue_cve_push(task_pk: int, task_fn) -> None:
    # Broker offline: the push task row stays 'queued' for a dashboard retry.
    safe_enqueue(task_fn, task_pk)
