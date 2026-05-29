"""Append-only audit log.

Mutability is enforced at *two* layers:

1. Application: ``AuditLogEntry.save`` refuses to update an existing row, and
   the model has no ``delete``-friendly admin.
2. Database: a Postgres trigger raises on UPDATE and DELETE against the
   underlying table (see ``audit/migrations/0002_append_only_trigger.py``).
   That makes the constraint impossible to bypass from the ORM, the admin,
   or even raw SQL through the Django connection.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models


class Action(models.TextChoices):
    ADVISORY_CREATED = "advisory.created"
    ADVISORY_VIEWED = "advisory.viewed"
    ADVISORY_EDITED = "advisory.edited"
    ADVISORY_STATE_CHANGED = "advisory.state_changed"
    ADVISORY_PROJECT_CHANGED = "advisory.project_changed"
    ADVISORY_ACCESS_REVIEW_DISMISSED = "advisory.access_review_dismissed"
    ADVISORY_SUBMITTED_FOR_REVIEW = "advisory.submitted_for_review"
    ADVISORY_REVIEW_APPROVED = "advisory.review_approved"
    ADVISORY_REVIEW_CHANGES_REQUESTED = "advisory.review_changes_requested"
    ADVISORY_REVIEW_APPROVAL_INVALIDATED = "advisory.review_approval_invalidated"
    ADVISORY_REVIEW_APPROVAL_REVOKED = "advisory.review_approval_revoked"
    ADVISORY_REVIEW_WITHDRAWN = "advisory.review_withdrawn"
    ADVISORY_PUBLISHED = "advisory.published"
    ADVISORY_DISMISSED = "advisory.dismissed"
    ADVISORY_REOPENED = "advisory.reopened"
    ACCESS_GRANTED = "access.granted"
    ACCESS_REVOKED = "access.revoked"
    INVITATION_CREATED = "invitation.created"
    INVITATION_REDEEMED = "invitation.redeemed"
    INVITATION_REVOKED = "invitation.revoked"
    COMMENT_CREATED = "comment.created"
    COMMENT_EDITED = "comment.edited"
    COMMENT_REDACTED = "comment.redacted"
    CVE_REQUESTED = "cve.requested"
    CVE_TASK_STATUS_CHANGED = "cve.task_status_changed"
    CVE_REQUEST_BANNED = "cve.request_banned"
    CVE_REQUEST_CANCELLED = "cve.request_cancelled"
    CVE_UNASSIGNED = "cve.unassigned"
    CVE_MARKED_REJECTED_AT_CVE_ORG = "cve.marked_rejected_at_cve_org"
    CVE_REASSIGNED_FROM_ORPHAN = "cve.reassigned_from_orphan"
    ORPHAN_REASSIGNMENT_REQUESTED = "cve.orphan_reassignment_requested"
    ORPHAN_REASSIGNMENT_RESOLVED = "cve.orphan_reassignment_resolved"
    REVIEW_TASK_STATUS_CHANGED = "review.task_status_changed"
    PUBLICATION_EXPORT_STARTED = "publication.export_started"
    PUBLICATION_EXPORT_COMPLETED = "publication.export_completed"
    PUBLICATION_EXPORT_FAILED = "publication.export_failed"
    PUBLICATION_OSV_GENERATED = "publication.osv_generated"
    PUBLICATION_CSAF_GENERATED = "publication.csaf_generated"
    PUBLICATION_CVE_GENERATED = "publication.cve_generated"
    PUBLICATION_GIT_COMMIT = "publication.git_commit"
    PUBLICATION_GIT_PUSH = "publication.git_push"
    PUBLICATION_GIT_PUSH_FAILED = "publication.git_push_failed"
    NOTIFICATION_PREFS_CHANGED = "notification.prefs_changed"
    GHSA_METADATA_FETCHED = "ghsa.metadata_fetched"
    GHSA_LINKED_ADVISORY_CREATED = "ghsa.linked_advisory_created"
    GHSA_CVE_PUSH_REQUESTED = "ghsa.cve_push_requested"
    GHSA_CVE_PUSH_SUCCEEDED = "ghsa.cve_push_succeeded"
    GHSA_CVE_PUSH_FAILED = "ghsa.cve_push_failed"
    GHSA_CVE_CONFLICT_DETECTED = "ghsa.cve_conflict_detected"
    GHSA_SYNC_RUN_STARTED = "ghsa.sync_run_started"
    GHSA_SYNC_RUN_FINISHED = "ghsa.sync_run_finished"
    GHSA_INSTALLATION_REGISTERED = "ghsa.installation_registered"
    GHSA_INSTALLATION_SUSPENDED = "ghsa.installation_suspended"
    GHSA_INSTALLATION_REMOVED = "ghsa.installation_removed"
    GHSA_WEBHOOK_RECEIVED = "ghsa.webhook_received"
    GHSA_WEBHOOK_REJECTED = "ghsa.webhook_rejected"
    PMI_PROJECT_REPOS_SYNCED = "pmi.project_repos_synced"
    # Triage flow (current). The intake form creates an Advisory(state=triage)
    # rather than a separate report row. Old REPORT_* values below remain in
    # the enum so existing audit rows stay readable; new code emits the
    # ADVISORY_TRIAGE_* / ADVISORY_FLAGGED_FOR_ROUTING actions instead.
    ADVISORY_TRIAGE_SUBMITTED = "advisory.triage_submitted"
    ADVISORY_TRIAGE_PROMOTED = "advisory.triage_promoted"
    ADVISORY_FLAGGED_FOR_ROUTING = "advisory.flagged_for_routing"
    ADVISORY_ROUTING_FLAG_CLEARED = "advisory.routing_flag_cleared"
    # Legacy intake actions — kept for read-only history, not emitted by new code.
    REPORT_SUBMITTED = "report.submitted"
    REPORT_TRIAGED_INTO_ADVISORY = "report.triaged_into_advisory"
    REPORT_DISMISSED = "report.dismissed"
    REPORT_PROJECT_REASSIGNED = "report.project_reassigned"
    REPORT_FLAGGED_FOR_ROUTING = "report.flagged_for_routing"


class AuditLogEntry(models.Model):
    """Single append-only audit log row."""

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    action = models.CharField(max_length=64, choices=Action.choices)
    advisory = models.ForeignKey(
        "advisories.Advisory",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_entries",
    )
    comment_id = models.BigIntegerField(null=True, blank=True)
    previous_value = models.JSONField(null=True, blank=True)
    new_value = models.JSONField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["created_at"]),
            models.Index(fields=["advisory", "created_at"]),
            models.Index(fields=["actor", "created_at"]),
            models.Index(fields=["action"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        actor = self.actor.email if self.actor else "system"
        return f"{self.created_at:%Y-%m-%d %H:%M} {actor} {self.action}"

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise PermissionError("AuditLogEntry is append-only; updates are not allowed.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError("AuditLogEntry is append-only; deletion is not allowed.")
