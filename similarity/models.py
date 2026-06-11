"""Duplicate-detection task tracking and the per-advisory fingerprint cache.

``SimilarityCheck`` mirrors ``publication.PublicationTask``: a task-state row
pinned (PROTECT) to the :class:`~advisories.models.AdvisoryVersion` whose
payload was judged, so results always describe immutable content rather than
live form data (INV-SIM-4). ``last_error`` is always written through
``audit.services.redact_secrets`` so an LLM API key or token-bearing URL never
reaches the row (INV-SIM-3).

``AdvisoryFingerprint`` is a *mutable cache* keyed by a content hash over the
duplicate-relevant subset of the advisory payload. It is deliberately not part
of ``Advisory.to_payload()``: creating or refreshing a fingerprint never
appends an ``AdvisoryVersion``.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models


class SimilarityCheckStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed"


class SimilarityCheck(models.Model):
    advisory = models.ForeignKey(
        "advisories.Advisory", on_delete=models.CASCADE, related_name="similarity_checks"
    )
    version = models.ForeignKey(
        "advisories.AdvisoryVersion",
        on_delete=models.PROTECT,
        related_name="similarity_checks",
    )
    status = models.CharField(
        max_length=16,
        choices=SimilarityCheckStatus.choices,
        default=SimilarityCheckStatus.QUEUED,
    )
    attempts = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True)
    # Human-readable short-circuit explanation ("No content to compare yet.").
    note = models.CharField(max_length=200, blank=True)
    # Size of the prefilter candidate pool that was sent to the judge call —
    # diagnostics for tuning SIMILARITY_CANDIDATE_LIMIT.
    candidate_pool_size = models.PositiveIntegerField(default=0)
    provider = models.CharField(max_length=32, blank=True)
    model = models.CharField(max_length=100, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=64, blank=True)
    enqueued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["advisory", "status"]),
        ]

    def __str__(self) -> str:
        return f"similarity check for {self.advisory_id} ({self.status})"


class SimilarityCandidate(models.Model):
    """One judged potential duplicate (up to five per succeeded check)."""

    # Not named ``check``: a field of that name shadows Django's
    # ``Model.check()`` system-check hook (models.E020).
    check_run = models.ForeignKey(
        SimilarityCheck, on_delete=models.CASCADE, related_name="candidates"
    )
    matched_advisory = models.ForeignKey(
        "advisories.Advisory", on_delete=models.CASCADE, related_name="similarity_matches"
    )
    # 0–100, clamped in service code — structured-output JSON schemas cannot
    # carry numeric bounds, so the model output is normalized before storage.
    confidence = models.PositiveSmallIntegerField()
    rationale = models.CharField(max_length=500, blank=True)
    rank = models.PositiveSmallIntegerField()

    class Meta:
        ordering = ["check_run", "rank"]
        constraints = [
            models.UniqueConstraint(
                fields=["check_run", "matched_advisory"], name="simcand_unique_match"
            ),
            models.UniqueConstraint(fields=["check_run", "rank"], name="simcand_unique_rank"),
        ]

    def __str__(self) -> str:
        return f"{self.matched_advisory_id} @ {self.confidence}% (check {self.check_run_id})"


class AdvisoryFingerprint(models.Model):
    """Cached LLM digest of an advisory, reused as judge-call input.

    ``content_hash`` covers the duplicate-relevant payload subset (see
    ``similarity.services``); a hash mismatch marks the row stale, and the
    advisory's next own check regenerates it in place.
    """

    advisory = models.OneToOneField(
        "advisories.Advisory", on_delete=models.CASCADE, related_name="llm_fingerprint"
    )
    content_hash = models.CharField(max_length=64)
    text = models.TextField()
    provider = models.CharField(max_length=32)
    model = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"fingerprint for {self.advisory_id}"
