"""Bookkeeping models for the GHSA integration.

Two append-friendly tables:

* ``GhsaCvePushTask`` — one row per attempt to push an EF-assigned CVE id
  back to the linked GHSA on GitHub. Lifecycle mirrors
  ``publication.PublicationTask``; a failed push does NOT roll back the
  internal ``Advisory.assigned_cve_id`` because that allocation was made
  out of the EF CNA pool and stands regardless of GitHub's reachability.

* ``GhsaSyncRun`` — one row per batch of GHSA sync work (single advisory,
  per-project, or org-wide). Acts as a coarse audit trail for the
  dashboard so operators can see "we discovered N new advisories and
  refreshed M in the last run, with K errors".
"""

from __future__ import annotations

from django.conf import settings
from django.db import models


class GhsaCvePushTaskStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed"


class GhsaCvePushTask(models.Model):
    advisory = models.ForeignKey(
        "advisories.Advisory", on_delete=models.CASCADE, related_name="ghsa_cve_push_tasks"
    )
    cve_id = models.CharField(max_length=32)
    status = models.CharField(
        max_length=16,
        choices=GhsaCvePushTaskStatus.choices,
        default=GhsaCvePushTaskStatus.QUEUED,
    )
    attempts = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    celery_task_id = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["advisory", "status"]),
        ]

    def __str__(self) -> str:
        return f"cve push {self.cve_id} → {self.advisory_id} ({self.status})"


class GhsaSyncRunScope(models.TextChoices):
    SINGLE = "single", "Single advisory"
    PROJECT = "project", "Project"
    ALL = "all", "All projects"
    PMI_MIRROR = "pmi_mirror", "PMI repo mirror only"


class GhsaSyncRunStatus(models.TextChoices):
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    PARTIAL = "partial", "Partial (some errors)"
    FAILED = "failed", "Failed"


class GhsaSyncRun(models.Model):
    scope = models.CharField(max_length=16, choices=GhsaSyncRunScope.choices)
    project = models.ForeignKey(
        "projects.Project",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ghsa_sync_runs",
    )
    advisory = models.ForeignKey(
        "advisories.Advisory",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ghsa_sync_runs",
    )
    status = models.CharField(
        max_length=16,
        choices=GhsaSyncRunStatus.choices,
        default=GhsaSyncRunStatus.RUNNING,
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    advisories_created = models.PositiveIntegerField(default=0)
    advisories_updated = models.PositiveIntegerField(default=0)
    errors_count = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]
        indexes = [
            models.Index(fields=["scope", "started_at"]),
            models.Index(fields=["project", "started_at"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self) -> str:
        return f"sync {self.scope} ({self.status}) @ {self.started_at:%Y-%m-%d %H:%M}"


# ---------------------------------------------------------------------------
# Multi-installation support
# ---------------------------------------------------------------------------


class GitHubAppAccountType(models.TextChoices):
    ORGANIZATION = "Organization", "Organization"
    USER = "User", "User"


class GitHubAppInstallation(models.Model):
    """A registered installation of the AdvisoryHub GitHub App.

    One row per GitHub account (org or user) that has installed the App.
    The ``installation_id`` is GitHub's; ``account_login`` is the org/user
    name used by the API as the ``owner`` segment of repo URLs. We route
    every API call by looking up the row matching the request's owner
    and using its installation token. There is no env-var fallback —
    when no row matches, the client raises and the operator must run
    ``manage.py discover_github_installations`` (or wait for an
    ``installation.created`` webhook).
    """

    installation_id = models.BigIntegerField(unique=True)
    account_login = models.CharField(max_length=100, unique=True)
    account_type = models.CharField(
        max_length=16,
        choices=GitHubAppAccountType.choices,
        default=GitHubAppAccountType.ORGANIZATION,
    )
    app_slug = models.CharField(max_length=100, blank=True)
    suspended_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["account_login"]
        indexes = [
            models.Index(fields=["suspended_at"]),
        ]

    def __str__(self) -> str:
        suffix = " (suspended)" if self.suspended_at else ""
        return f"{self.account_login} (id={self.installation_id}){suffix}"

    @property
    def is_active(self) -> bool:
        return self.suspended_at is None


class WebhookDeliveryStatus(models.TextChoices):
    RECEIVED = "received", "Received"
    PROCESSED = "processed", "Processed"
    SKIPPED = "skipped", "Skipped"
    FAILED = "failed", "Failed"


class WebhookDelivery(models.Model):
    """One row per inbound GitHub webhook delivery.

    Provides idempotency (unique on the GitHub-issued ``delivery_id``)
    and a coarse audit trail. Body bytes are deliberately not persisted —
    the audit log captures the event/action and the resulting state
    changes; storing the raw payload would just duplicate information
    available elsewhere and increases the surface area for sensitive data
    at rest.
    """

    delivery_id = models.CharField(max_length=64, unique=True)
    event = models.CharField(max_length=64)
    action = models.CharField(max_length=64, blank=True)
    installation_id = models.BigIntegerField(null=True, blank=True)
    status = models.CharField(
        max_length=16,
        choices=WebhookDeliveryStatus.choices,
        default=WebhookDeliveryStatus.RECEIVED,
    )
    last_error = models.TextField(blank=True)
    received_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-received_at"]
        indexes = [
            models.Index(fields=["event", "action"]),
            models.Index(fields=["status", "received_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.event}.{self.action} ({self.status}) @ {self.received_at:%Y-%m-%d %H:%M}"
