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
    PUBLICATION_TASK_REAPED = "publication.task_reaped"
    # LLM-assisted duplicate detection (similarity app). Durable: low-volume
    # (a few rows per advisory creation) and security-relevant — they record
    # when advisory content was sent to the configured LLM provider.
    SIMILARITY_CHECK_STARTED = "similarity.check_started"
    SIMILARITY_CHECK_COMPLETED = "similarity.check_completed"
    SIMILARITY_CHECK_FAILED = "similarity.check_failed"
    SIMILARITY_CHECK_REAPED = "similarity.check_reaped"
    NOTIFICATION_PREFS_CHANGED = "notification.prefs_changed"
    # One entry per recipient per delivered notification (incl. invitation
    # emails, which create no inbox row). High-volume and PII-bearing
    # (recipient email in metadata) → routed to the ephemeral access log below.
    NOTIFICATION_SENT = "notification.sent"
    GHSA_METADATA_FETCHED = "ghsa.metadata_fetched"
    GHSA_LINKED_ADVISORY_CREATED = "ghsa.linked_advisory_created"
    GHSA_CVE_PUSH_REQUESTED = "ghsa.cve_push_requested"
    GHSA_CVE_PUSH_SUCCEEDED = "ghsa.cve_push_succeeded"
    GHSA_CVE_PUSH_FAILED = "ghsa.cve_push_failed"
    GHSA_CVE_PUSH_REAPED = "ghsa.cve_push_reaped"
    GHSA_CVE_CONFLICT_DETECTED = "ghsa.cve_conflict_detected"
    GHSA_SYNC_RUN_STARTED = "ghsa.sync_run_started"
    GHSA_SYNC_RUN_FINISHED = "ghsa.sync_run_finished"
    GHSA_INSTALLATION_REGISTERED = "ghsa.installation_registered"
    GHSA_INSTALLATION_SUSPENDED = "ghsa.installation_suspended"
    GHSA_INSTALLATION_REMOVED = "ghsa.installation_removed"
    GHSA_WEBHOOK_RECEIVED = "ghsa.webhook_received"
    GHSA_WEBHOOK_REJECTED = "ghsa.webhook_rejected"
    PMI_PROJECT_REPOS_SYNCED = "pmi.project_repos_synced"
    # Security-team roster sync (authenticated Eclipse API → shadow users).
    # SECURITY_ROSTER_SYNCED is per-sync-run machine chatter (ephemeral, below);
    # SHADOW_USER_LINKED records the one-time shadow→real promotion at first
    # login and stays in the durable ledger.
    SECURITY_ROSTER_SYNCED = "roster.synced"
    SHADOW_USER_LINKED = "roster.shadow_linked"
    # Authentication events: a successful sign-in, sign-out, a rejected/aborted
    # attempt (no session created), and the pre-publish step-up re-auth. These
    # are access telemetry — routed to the ephemeral access log below, where the
    # source IP is shown and retention pruning + forget_user clear the PII.
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_STEP_UP_COMPLETED = "auth.step_up_completed"
    # Site-wide maintenance mode toggle (admin console). See INV-MAINT-1.
    MAINTENANCE_ENABLED = "maintenance.enabled"
    MAINTENANCE_DISABLED = "maintenance.disabled"
    # Admin bans/unbans a user account (admin console). The banned user is the
    # target (in metadata); the actor is the admin. Durable — these are
    # low-volume, security-relevant governance events. See INV-AUTH-8.
    USER_BANNED = "user.banned"
    USER_UNBANNED = "user.unbanned"
    # GDPR right-to-be-forgotten erasure (admin console or `manage.py
    # forget_user`). Durable governance event: the actor is the requesting
    # operator (null on the CLI path), the forgotten subject's pk + the per-
    # source scrub counters live in metadata, with no PII inside. See
    # ``audit.retention.forget_user``.
    USER_FORGOTTEN = "user.forgotten"
    # Retention sweep of the durable ledger itself (admin console or `manage.py
    # prune_audit`). Durable governance event: the actor is the requesting
    # operator (null on the CLI path); the horizon, exact cutoff, and deleted
    # row count live in metadata. See ``audit.retention.prune_audit_older_than``.
    AUDIT_PRUNED = "audit.pruned"
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


# Actions routed to the retention-managed, monthly-partitioned access log
# (:class:`AccessLogEntry`) instead of the durable ledger. This is a deliberate
# ALLOWLIST: only actions named here become subject to DROP PARTITION pruning.
# Every other action stays in the append-only :class:`AuditLogEntry` forever, so
# a newly-added ``Action`` is retained in the ledger until a human explicitly
# moves it here.
#
# INVARIANT: this set must stay disjoint from the advisory-timeline tiers
# (``advisories.timeline``). An ephemeral action that became timeline-visible
# would silently vanish when its month-partition is dropped. A cross-app test
# enforces the disjointness (``advisories/tests/test_access_log_disjoint.py``).
# See INV-AUDIT-5 in docs/specification/invariant.md.
EPHEMERAL_ACTIONS: frozenset[str] = frozenset(
    {
        Action.ADVISORY_VIEWED,
        Action.GHSA_WEBHOOK_RECEIVED,
        Action.GHSA_WEBHOOK_REJECTED,
        Action.GHSA_SYNC_RUN_STARTED,
        Action.GHSA_SYNC_RUN_FINISHED,
        Action.GHSA_METADATA_FETCHED,
        Action.PMI_PROJECT_REPOS_SYNCED,
        Action.SECURITY_ROSTER_SYNCED,
        Action.AUTH_LOGIN,
        Action.AUTH_LOGOUT,
        Action.AUTH_LOGIN_FAILED,
        Action.AUTH_STEP_UP_COMPLETED,
        Action.NOTIFICATION_SENT,
    }
)


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


class AccessLogEntry(models.Model):
    """High-volume, retention-managed access / telemetry events.

    A deliberately lower-tier sibling of :class:`AuditLogEntry`. It holds the
    actions in :data:`EPHEMERAL_ACTIONS` — advisory views plus GHSA/PMI machine
    chatter — none of which appear on any advisory timeline. Unlike the ledger,
    this table is:

    * **Range-partitioned by month on ``created_at``.** The physical table is
      created with ``PARTITION BY RANGE`` in migration ``0003`` (the ORM only
      tracks the logical columns). Retention is a ``DROP PARTITION`` of months
      older than the horizon — O(1), no per-row ``DELETE``, no dead tuples (see
      :mod:`audit.partitions`).
    * **Not protected by the append-only triggers.** It must be droppable.
      Writes are still append-only at the *application* layer (``save`` refuses
      to update an existing row), but the database permits ``DELETE``/``DROP``
      so retention and ``forget_user`` can do their work.

    Because the table is partitioned, its real primary key is the composite
    ``(id, created_at)`` (Postgres requires the partition key in the PK); Django
    still tracks the bare ``id`` in model state, which is harmless since these
    rows are never updated or fetched by a bare pk in a hot path.

    See INV-AUDIT-5 in docs/specification/invariant.md.
    """

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
        related_name="access_log_entries",
    )
    metadata = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["created_at"], name="acclog_created_idx"),
            models.Index(fields=["advisory", "created_at"], name="acclog_adv_created_idx"),
            models.Index(fields=["actor", "created_at"], name="acclog_actor_created_idx"),
            models.Index(fields=["action"], name="acclog_action_idx"),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        actor = self.actor.email if self.actor else "system"
        return f"{self.created_at:%Y-%m-%d %H:%M} {actor} {self.action}"

    def save(self, *args, **kwargs):
        # Application-layer write-once. The DB has no append-only trigger here
        # (the table must stay droppable for retention), so this is the only
        # guard against accidental ORM updates. Deletes are intentionally
        # allowed (retention / forget_user).
        if self.pk is not None:
            raise PermissionError("AccessLogEntry is append-only; updates are not allowed.")
        super().save(*args, **kwargs)
