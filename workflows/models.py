"""CVE request and advisory review tasks.

These models are the durable record of in-flight workflow work. State
transitions go exclusively through ``workflows.services`` — never set
``status`` directly — so audit and notification side-effects stay
consistent.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models
from django.db.models import Q

from advisories.validators import CVE_ID_RE, validate_cve_id

__all__ = [
    "CVE_ID_RE",
    "CveRequestStatus",
    "CveRequestTask",
    "OrphanCve",
    "OrphanCveReassignmentStatus",
    "OrphanCveReassignmentTask",
    "OrphanCveStatus",
    "ReviewTask",
    "ReviewTaskStatus",
    "validate_cve_id",
]


class CveRequestStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RESERVED = "reserved", "Reserved"
    REJECTED = "rejected", "Rejected"
    CANCELLED = "cancelled", "Cancelled"


class OrphanCveStatus(models.TextChoices):
    ORPHANED = "orphaned", "Orphaned (awaiting cve.org rejection)"
    MARKED_REJECTED = "marked_rejected", "Marked as rejected at cve.org"
    # Terminal: the CVE was reattached to its original advisory via the
    # reopen flow. Reached either directly (orphan was still ``orphaned``
    # when reopen ran) or via an ``OrphanCveReassignmentTask`` resolution
    # where the admin recorded "rejection undone at cve.org".
    REASSIGNED = "reassigned", "Reassigned back to advisory"


class OrphanCveReassignmentStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RESOLVED_REASSIGNED = "resolved_reassigned", "Resolved — CVE reattached"
    RESOLVED_REPLACED = "resolved_replaced", "Resolved — replaced with a new CVE"


class ReviewTaskStatus(models.TextChoices):
    OPEN = "open", "Open"
    APPROVED = "approved", "Approved"
    CHANGES_REQUESTED = "changes_requested", "Changes requested"
    WITHDRAWN = "withdrawn", "Withdrawn"


class CveRequestTask(models.Model):
    """A request for the top-level security team to reserve a CVE at MITRE."""

    advisory = models.ForeignKey(
        "advisories.Advisory",
        on_delete=models.CASCADE,
        related_name="cve_requests",
    )
    status = models.CharField(
        max_length=16, choices=CveRequestStatus.choices, default=CveRequestStatus.QUEUED
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cve_requests_assigned",
    )
    cve_id = models.CharField(max_length=32, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["advisory", "status"]),
        ]
        constraints = [
            # At most one open (queued) CVE request per advisory. Reserved,
            # rejected, and cancelled tasks don't count — reserved is gated by
            # ``Advisory.assigned_cve_id``; rejected can be re-requested
            # unless ``Advisory.cve_requests_banned`` is set; cancelled is a
            # terminal system state (e.g. advisory dismissed).
            models.UniqueConstraint(
                fields=["advisory"],
                condition=Q(status="queued"),
                name="cve_request_one_open_per_advisory",
            ),
        ]

    def __str__(self) -> str:
        return f"CVE request for {self.advisory_id} ({self.status})"

    def clean(self) -> None:
        super().clean()
        if self.cve_id:
            validate_cve_id(self.cve_id)


class OrphanCve(models.Model):
    """A CVE that was previously assigned to an advisory and has since been
    unassigned by an admin. Stays in the dashboard queue until the admin
    records that it was marked rejected at cve.org (an out-of-band action)."""

    cve_id = models.CharField(max_length=32, unique=True, validators=[validate_cve_id])
    previous_advisory = models.ForeignKey(
        "advisories.Advisory",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="orphaned_cves",
    )
    # Snapshot of the advisory's public identifier at unassign time so the
    # orphan stays interpretable even if the originating advisory is later
    # deleted (the ``previous_advisory`` FK becomes NULL in that case).
    previous_advisory_label = models.CharField(max_length=32, blank=True)
    status = models.CharField(
        max_length=24,
        choices=OrphanCveStatus.choices,
        default=OrphanCveStatus.ORPHANED,
    )
    unassigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    unassigned_at = models.DateTimeField(auto_now_add=True)
    unassign_reason = models.TextField()
    marked_rejected_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    marked_rejected_at = models.DateTimeField(null=True, blank=True)
    marked_rejected_notes = models.TextField(blank=True)

    class Meta:
        ordering = ["-unassigned_at"]
        indexes = [models.Index(fields=["status", "unassigned_at"])]

    def __str__(self) -> str:
        return f"orphan {self.cve_id} ({self.status})"


class OrphanCveReassignmentTask(models.Model):
    """Admin to-do raised when reopen meets an already-rejected orphan CVE.

    When an advisory is reopened (see ``advisories.services.reopen_advisory``)
    and its previously-assigned CVE is on an :class:`OrphanCve` that is
    already ``marked_rejected`` at cve.org, the reassignment can't be done
    silently — an admin has to try to undo the rejection out-of-band at
    cve.org. This row queues that work and records the outcome:

    * ``resolved_reassigned``: admin convinced cve.org to revert the
      rejection; the CVE is reattached to the advisory and the orphan flips
      to :class:`OrphanCveStatus.REASSIGNED`.
    * ``resolved_replaced``: admin couldn't undo the rejection and entered a
      replacement CVE id on the resolution form; a fresh
      :class:`CveRequestTask` is created in ``RESERVED`` state for the new
      id, the orphan stays ``marked_rejected``.

    The advisory itself moves back to ``draft`` / ``triage`` *immediately*
    when reopen runs — this task lives separately in the admin inbox so the
    owner doesn't have to wait on admin action to keep working.
    """

    orphan_cve = models.ForeignKey(
        OrphanCve,
        on_delete=models.PROTECT,
        related_name="reassignment_tasks",
    )
    advisory = models.ForeignKey(
        "advisories.Advisory",
        on_delete=models.CASCADE,
        related_name="orphan_reassignment_tasks",
    )
    status = models.CharField(
        max_length=24,
        choices=OrphanCveReassignmentStatus.choices,
        default=OrphanCveReassignmentStatus.QUEUED,
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    replacement_cve_id = models.CharField(max_length=32, blank=True)
    resolution_notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["advisory", "status"]),
        ]
        constraints = [
            # At most one open reassignment task per orphan — preventing
            # concurrent reopens against the same orphan from queueing
            # duplicate admin work.
            models.UniqueConstraint(
                fields=["orphan_cve"],
                condition=Q(status="queued"),
                name="orphan_reassignment_one_open_per_orphan",
            ),
        ]

    def __str__(self) -> str:
        return f"reassignment for {self.orphan_cve.cve_id} ({self.status})"

    def clean(self) -> None:
        super().clean()
        if self.replacement_cve_id:
            validate_cve_id(self.replacement_cve_id)


class ReviewTask(models.Model):
    """A review submission pinned to a specific :class:`AdvisoryVersion`.

    ``version`` is the frozen content the reviewer is judging. Successive
    review attempts (after changes_requested/rejected and a re-submission)
    create new ReviewTask rows; each pins whichever version was current
    when it was submitted. The advisory's ``review_status`` mirrors the
    latest task's outcome.
    """

    advisory = models.ForeignKey(
        "advisories.Advisory", on_delete=models.CASCADE, related_name="review_tasks"
    )
    version = models.ForeignKey(
        "advisories.AdvisoryVersion",
        on_delete=models.PROTECT,
        related_name="review_tasks",
    )
    status = models.CharField(
        max_length=24, choices=ReviewTaskStatus.choices, default=ReviewTaskStatus.OPEN
    )
    submitted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviews_done",
    )
    decision_notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["advisory", "status"]),
        ]

    def __str__(self) -> str:
        return f"review for {self.advisory_id} ({self.status})"
