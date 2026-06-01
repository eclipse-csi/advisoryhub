"""Advisory and AdvisoryVersion models.

The advisory lifecycle is intentionally narrow — four states only — per the
specification: ``triage`` (untrusted incoming intake), ``draft`` (curated by
the security team), ``published`` (exported to OSV+CSAF), and ``dismissed``.
Review and publication are modeled with separate status fields plus pointers
into the immutable :class:`AdvisoryVersion` log, *not* additional lifecycle
states. Every content change to an :class:`Advisory` appends a new
``AdvisoryVersion`` row, mirroring how :class:`comments.models.CommentVersion`
preserves comment edit history.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import connection, models

from .identifiers import generate_advisory_id, is_valid_advisory_id
from .validators import (
    validate_advisory_id,
    validate_affected,
    validate_aliases,
    validate_credits,
    validate_cve_id,
    validate_cwe_ids,
    validate_ghsa_id,
    validate_references,
    validate_severity,
)

MAX_ID_RETRIES = 8

# Fields that are sourced from GHSA when an advisory is GHSA-linked. The
# advisory edit form must render these as read-only; service code that
# writes any of these for a GHSA-linked advisory should raise unless the
# write originates from the sync path.
GHSA_READONLY_FIELDS = frozenset(
    {
        "summary",
        "details",
        "aliases",
        "references",
        "affected",
        "severity",
        "cwe_ids",
        "credits",
    }
)


class State(models.TextChoices):
    TRIAGE = "triage", "Triage"
    DRAFT = "draft", "Draft"
    PUBLISHED = "published", "Published"
    DISMISSED = "dismissed", "Dismissed"


class ReviewStatus(models.TextChoices):
    NONE = "none", "Not submitted"
    SUBMITTED = "submitted", "Submitted for review"
    CHANGES_REQUESTED = "changes_requested", "Changes requested"
    APPROVED = "approved", "Approved"


class Kind(models.TextChoices):
    NATIVE = "native", "Native"
    GHSA_LINKED = "ghsa_linked", "GHSA-linked"


class GhsaState(models.TextChoices):
    UNKNOWN = "unknown", "Unknown"
    DRAFT = "draft", "Draft"
    TRIAGE = "triage", "Triage"
    PUBLISHED = "published", "Published"
    CLOSED = "closed", "Closed"
    WITHDRAWN = "withdrawn", "Withdrawn"


class GhsaCvePushStatus(models.TextChoices):
    NONE = "none", "Not requested"
    PENDING = "pending", "Pending"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed"


class AdvisoryQuerySet(models.QuerySet):
    """Manager queryset that refuses bulk deletion.

    Mirrors the application-layer guard on :class:`AdvisoryVersion` and
    :class:`audit.models.AuditLogEntry`: advisories are the immutable
    spine that versions, publications and audit entries hang off, so the
    ORM should never offer a route to remove them. Dev-only seed reset
    has its own explicit escape via :func:`_unsafe_dev_reset_bypass`.
    """

    def delete(self):  # noqa: DJ012 — intentional override
        raise PermissionError(
            "Advisory rows are non-deletable; "
            "use advisories.models._unsafe_dev_reset_bypass() in seed scripts only."
        )


# Assignment form (rather than subclassing) keeps django-stubs happy: it can't
# resolve ``Manager.from_queryset(...)`` as a dynamic base class, but it does
# model the call's return type. There's no extra manager behaviour to add.
AdvisoryManager = models.Manager.from_queryset(AdvisoryQuerySet)


@contextmanager
def _unsafe_dev_reset_bypass():
    """Temporarily allow advisory deletion. Dev/seed only — never call from prod code.

    Two effects, both reverted on exit:

    * Lowers Postgres ``session_replication_role`` to ``replica`` for the
      current transaction, which disables the ``advisory_no_delete``
      trigger (and any other non-replication triggers) without dropping
      them.
    * Lets the caller use the bypassing ORM path
      :func:`_unsafe_dev_reset_delete_queryset` to actually issue the
      bulk delete; the regular ``AdvisoryQuerySet.delete()`` still
      raises.

    Mirrors :func:`audit.retention._audit_trigger_bypass`. Only intended
    for ``seed_demo --reset``; production code paths must not invoke it.
    """
    with connection.cursor() as cur:
        cur.execute("SET LOCAL session_replication_role = replica")
        try:
            yield
        finally:
            cur.execute("SET LOCAL session_replication_role = origin")


def _unsafe_dev_reset_delete_queryset(qs):
    """Bulk-delete an Advisory queryset, bypassing the manager guard.

    Must be called inside :func:`_unsafe_dev_reset_bypass` on Postgres so
    the DB trigger is disabled for the surrounding transaction. Dev-only.
    """
    return models.QuerySet.delete(qs)


class Advisory(models.Model):
    advisory_id = models.CharField(max_length=32, unique=True, validators=[validate_advisory_id])
    project = models.ForeignKey(
        "projects.Project", on_delete=models.PROTECT, related_name="advisories"
    )

    # Lifecycle (the canonical four states: triage → draft → published, or
    # dismissed from triage/draft). Default is DRAFT — only the public intake
    # path creates rows with state=TRIAGE, via advisories.services.submit_triage_report.
    state = models.CharField(max_length=16, choices=State.choices, default=State.DRAFT)

    # Review workflow (separate from lifecycle)
    review_status = models.CharField(
        max_length=24, choices=ReviewStatus.choices, default=ReviewStatus.NONE
    )
    submitted_for_review_at = models.DateTimeField(null=True, blank=True)
    submitted_for_review_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )

    # OSV-aligned content
    summary = models.CharField(max_length=300, blank=True)
    details = models.TextField(blank=True)
    aliases = models.JSONField(default=list, blank=True, validators=[validate_aliases])
    references = models.JSONField(default=list, blank=True, validators=[validate_references])
    affected = models.JSONField(default=list, blank=True, validators=[validate_affected])
    severity = models.JSONField(default=list, blank=True, validators=[validate_severity])
    cwe_ids = models.JSONField(default=list, blank=True, validators=[validate_cwe_ids])
    credits = models.JSONField(default=list, blank=True, validators=[validate_credits])

    # Lifecycle timestamps and reasons
    published_at = models.DateTimeField(null=True, blank=True)
    modified_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    withdrawn_reason = models.TextField(blank=True)
    dismissed_reason = models.TextField(blank=True)
    # Records which non-terminal state the advisory was in immediately before
    # being dismissed (``triage`` or ``draft``). Set by ``dismiss_triage`` and
    # the draft-dismiss view; consulted by ``reopen_advisory`` to decide where
    # to send the advisory back to. Kept after reopen as historical metadata.
    dismissed_from_state = models.CharField(
        max_length=16, choices=State.choices, blank=True, default=""
    )

    # Re-publication: set true when a published advisory is edited
    republish_required = models.BooleanField(default=False)

    # Access review: set when the advisory's project is reassigned, prompting
    # writers to prune grants that no longer apply. Cleared when a writer
    # dismisses the banner.
    access_review_required_at = models.DateTimeField(null=True, blank=True)

    # CVE assigned by the Eclipse Foundation acting as CNA. Distinct from the
    # editable ``aliases`` list: this is write-once, set by the CVE workflow
    # service on RESERVED, and merged into OSV/CSAF output at serialization
    # time so the editor cannot rename or remove it via the aliases formset.
    assigned_cve_id = models.CharField(max_length=32, blank=True, validators=[validate_cve_id])

    # When true, admins have disabled further CVE requests on this advisory
    # (anti-abuse switch flipped at rejection time).
    cve_requests_banned = models.BooleanField(default=False)

    # ---- GHSA-linked variant -------------------------------------------
    # AdvisoryHub treats some advisories as a *bridge* over a GitHub-hosted
    # Security Advisory (GHSA): metadata is synced from GitHub (read-only
    # in AdvisoryHub), CVE id allocation is initiated here and pushed back
    # to GitHub, and publication is gated on the upstream GHSA itself
    # being published. ``kind`` is set at creation and is immutable.
    kind = models.CharField(max_length=16, choices=Kind.choices, default=Kind.NATIVE)
    ghsa_id = models.CharField(max_length=32, blank=True, validators=[validate_ghsa_id])
    ghsa_owner = models.CharField(max_length=100, blank=True)
    ghsa_repo = models.CharField(max_length=200, blank=True)
    ghsa_metadata = models.JSONField(null=True, blank=True)
    ghsa_metadata_synced_at = models.DateTimeField(null=True, blank=True)
    ghsa_state = models.CharField(
        max_length=16, choices=GhsaState.choices, default=GhsaState.UNKNOWN, blank=True
    )
    ghsa_cve_push_status = models.CharField(
        max_length=16, choices=GhsaCvePushStatus.choices, default=GhsaCvePushStatus.NONE, blank=True
    )
    ghsa_cve_push_attempted_at = models.DateTimeField(null=True, blank=True)
    # Conflict markers — set when sync sees GHSA's cve_id != our
    # assigned_cve_id. We never overwrite our value; an admin must
    # reconcile (re-push the EF-assigned CVE to GHSA, or unassign
    # internally and accept the GHSA value).
    ghsa_cve_conflict_detected_at = models.DateTimeField(null=True, blank=True)
    ghsa_cve_conflict_ghsa_value = models.CharField(max_length=64, blank=True)

    objects = AdvisoryManager()

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["state"]),
            models.Index(fields=["project", "state"]),
            models.Index(fields=["review_status"]),
            models.Index(fields=["kind"]),
            models.Index(fields=["ghsa_id"]),
        ]
        constraints = [
            # A GHSA id maps to a single AdvisoryHub advisory. We enforce
            # uniqueness only when ghsa_id is non-empty (native advisories
            # share the empty string and must not collide).
            models.UniqueConstraint(
                fields=["ghsa_id"],
                condition=models.Q(ghsa_id__gt=""),
                name="advisory_ghsa_id_unique_when_set",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.advisory_id} ({self.get_state_display()})"

    # ---- validation -------------------------------------------------------

    def clean(self) -> None:
        super().clean()
        if self.advisory_id and not is_valid_advisory_id(self.advisory_id):
            raise ValidationError({"advisory_id": "Invalid advisory ID format."})
        if self.state == State.DISMISSED and not self.dismissed_reason.strip():
            raise ValidationError({"dismissed_reason": "Required when dismissing an advisory."})
        # ``kind`` is set at create time and must never flip — flipping it
        # would either orphan an upstream GHSA (native → ghsa_linked) or
        # silently strip the bridge metadata (ghsa_linked → native).
        if self.pk is not None:
            existing_kind = (
                Advisory.objects.filter(pk=self.pk).values_list("kind", flat=True).first()
            )
            if existing_kind is not None and existing_kind != self.kind:
                raise ValidationError({"kind": "Advisory kind is immutable after creation."})
        if self.kind == Kind.GHSA_LINKED:
            if not self.ghsa_id:
                raise ValidationError({"ghsa_id": "Required for GHSA-linked advisories."})
            if not (self.ghsa_owner and self.ghsa_repo):
                raise ValidationError({"ghsa_owner": "GHSA-linked advisories need owner and repo."})

    # ---- ID generation ----------------------------------------------------

    @classmethod
    def _generate_unique_id(cls) -> str:
        for _ in range(MAX_ID_RETRIES):
            candidate = generate_advisory_id()
            if not cls.objects.filter(advisory_id=candidate).exists():
                return candidate
        raise RuntimeError(  # pragma: no cover — astronomically unlikely
            "Could not generate a unique advisory ID after retries."
        )

    def save(self, *args, **kwargs):
        if not self.advisory_id:
            self.advisory_id = self._generate_unique_id()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError(
            "Advisory rows are non-deletable; published/audited identity is permanent."
        )

    # ---- derived state ----------------------------------------------------

    @property
    def is_mature_publisher_eligible_review_status(self) -> bool:
        """Whether this advisory may be published without a fresh approval.

        True iff it has an APPROVED review, or its project is a mature
        publisher (review optional). Consumed by
        ``advisories.permissions.can_publish``.
        """
        if self.review_status == ReviewStatus.APPROVED:
            return True
        return self.project.is_mature_publisher

    # ---- payload ----------------------------------------------------------

    def to_payload(self) -> dict:
        """Frozen-content representation, written into AdvisoryVersion rows."""
        return {
            "advisory_id": self.advisory_id,
            "project_slug": self.project.slug,
            # Pinned so downstream exports (e.g. the CVE record's affected
            # ``vendor``) read an immutable value rather than the live Project
            # row — a project rename must not retro-change a published record.
            "project_name": self.project.name,
            "summary": self.summary,
            "details": self.details,
            "aliases": copy.deepcopy(self.aliases),
            "assigned_cve_id": self.assigned_cve_id,
            "references": copy.deepcopy(self.references),
            "affected": copy.deepcopy(self.affected),
            "severity": copy.deepcopy(self.severity),
            "cwe_ids": copy.deepcopy(self.cwe_ids),
            "credits": copy.deepcopy(self.credits),
            "withdrawn_reason": self.withdrawn_reason,
            # Provenance for the GHSA-linked variant. Native advisories
            # carry ``kind="native"`` and empty ghsa_* fields here.
            "kind": self.kind,
            "ghsa_id": self.ghsa_id,
            "ghsa_owner": self.ghsa_owner,
            "ghsa_repo": self.ghsa_repo,
            "ghsa_metadata_synced_at": (
                self.ghsa_metadata_synced_at.isoformat() if self.ghsa_metadata_synced_at else None
            ),
        }


class AdvisoryVersion(models.Model):
    """Append-only revision history for :class:`Advisory` content.

    ``version=1`` is the state at creation. Each subsequent edit appends a
    new row carrying the frozen :meth:`Advisory.to_payload` at that moment.
    Workflow records (``workflows.ReviewTask``, ``publication.PublicationTask``)
    FK into this table to pin the exact content a reviewer judged or a
    publisher exported. Rows are immutable — ``save()`` on an existing row
    and ``delete()`` both raise, mirroring
    :class:`comments.models.CommentVersion`.
    """

    advisory = models.ForeignKey(Advisory, on_delete=models.CASCADE, related_name="versions")
    version = models.PositiveIntegerField()
    payload = models.JSONField()
    editor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:  # noqa: DJ012
        ordering = ["advisory", "version"]
        unique_together = [("advisory", "version")]
        indexes = [models.Index(fields=["advisory", "version"])]

    def __str__(self) -> str:
        return f"v{self.version} of {self.advisory.advisory_id}"

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise PermissionError("AdvisoryVersion is append-only; existing rows cannot be saved.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError("AdvisoryVersion is append-only; deletion not allowed.")


class AdvisoryIntakeMetadata(models.Model):
    """Sidecar holding intake-only signal for advisories that originated as
    public reports.

    Created at the same moment as an ``Advisory(state=TRIAGE)`` by the public
    intake form. Carries reporter identity (only when authenticated via OIDC),
    submission fingerprints (IP/UA) used for spam/abuse analysis, and the
    admin-routing flag for the triager workflow. Surviving the
    ``triage → draft`` transition gives provenance for the curated advisory;
    PII fields are scrubbed by ``audit.retention.forget_user``.

    Reporter email is **never stored as form input**. The only way to derive
    an email is via ``reporter_user.email`` (which OIDC has verified before
    we ever saw it). Anonymous submitters cannot supply an email; they may
    optionally set ``reporter_display_name`` for crediting only.
    """

    advisory = models.OneToOneField(
        "advisories.Advisory",
        on_delete=models.CASCADE,
        related_name="intake",
    )
    reporter_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        help_text="Set iff the submitter was authenticated. OIDC-verified identity.",
    )
    reporter_display_name = models.CharField(
        max_length=200,
        blank=True,
        help_text="Optional free-text name for crediting. Never used for authorization.",
    )
    submitted_ip = models.GenericIPAddressField(null=True, blank=True)
    submitted_user_agent = models.CharField(max_length=512, blank=True)

    # Admin-routing flag. Set automatically when the intake project is the
    # ``unsorted`` sentinel, or raised by a team-member triager who spots a
    # misrouted report. Once raised, only admins may act (services re-check).
    needs_admin_routing = models.BooleanField(default=False, db_index=True)
    admin_routing_note = models.TextField(blank=True)
    flagged_for_routing_at = models.DateTimeField(null=True, blank=True)
    flagged_for_routing_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )

    submitted_at = models.DateTimeField(auto_now_add=True, db_index=True)
    pii_cleared_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["needs_admin_routing"]),
            models.Index(fields=["submitted_at"]),
        ]

    def __str__(self) -> str:
        return f"intake:{self.advisory.advisory_id}"
