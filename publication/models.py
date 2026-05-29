"""Publication task tracking, artifact storage, and per-environment overrides.

The big invariant carried by these tables: an advisory is *not* considered
published until a ``PublicationTask`` reaches ``status=succeeded``. Until
then the advisory stays in ``draft`` state and any failure is visible to
the dashboard for retry. ``last_error`` is always written through
``audit.services.redact_secrets`` so a leaked Git URL/token never makes it
into the row.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models


class PublicationTaskStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed"


class PublicationTask(models.Model):
    advisory = models.ForeignKey(
        "advisories.Advisory", on_delete=models.CASCADE, related_name="publication_tasks"
    )
    version = models.ForeignKey(
        "advisories.AdvisoryVersion",
        on_delete=models.PROTECT,
        related_name="publication_tasks",
    )
    status = models.CharField(
        max_length=16,
        choices=PublicationTaskStatus.choices,
        default=PublicationTaskStatus.QUEUED,
    )
    attempts = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=64, blank=True)
    enqueued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    commit_sha = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["advisory", "status"]),
        ]

    def __str__(self) -> str:
        return f"publication for {self.advisory_id} ({self.status})"


class PublicationArtifact(models.Model):
    """Generated OSV/CSAF JSON for a particular publication task.

    Stored so the dashboard can preview exactly what was committed (or what
    was about to be, when a task failed). Validation errors live on
    ``PublicationTask.last_error`` rather than here.
    """

    class Kind(models.TextChoices):
        OSV = "osv", "OSV"
        CSAF = "csaf", "CSAF"
        CVE = "cve", "CVE"

    task = models.ForeignKey(PublicationTask, on_delete=models.CASCADE, related_name="artifacts")
    kind = models.CharField(max_length=8, choices=Kind.choices)
    path = models.CharField(max_length=255)
    content = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("task", "kind")]
        ordering = ["task", "kind"]

    def __str__(self) -> str:
        return f"{self.kind} for task {self.task_id}"


class PublicationRepositoryConfig(models.Model):
    """Optional DB-stored override of the env-driven publication repo config.

    Useful if AdvisoryHub manages multiple downstream publication targets
    in the future. For Phase D the env-only mode is the default; if a row
    is marked ``is_active=True`` the publication service uses it instead.
    """

    name = models.SlugField(max_length=64, unique=True)
    is_active = models.BooleanField(default=False)
    repo_url = models.CharField(max_length=512)
    branch = models.CharField(max_length=128, default="main")
    auth_method = models.CharField(
        max_length=8,
        choices=[("ssh", "SSH key"), ("token", "HTTPS token")],
        default="ssh",
    )
    ssh_key_path = models.CharField(max_length=512, blank=True)
    token = models.CharField(max_length=512, blank=True)
    commit_author_name = models.CharField(max_length=200)
    commit_author_email = models.EmailField()
    osv_path_template = models.CharField(max_length=255, default="osv/{year}/{advisory_id}.json")
    csaf_path_template = models.CharField(max_length=255, default="csaf/{year}/{advisory_id}.json")
    cve_path_template = models.CharField(
        max_length=255, default="cves/{year}/{bucket}/{cve_id}.json"
    )

    class Meta:
        verbose_name = "publication repository config"

    def __str__(self) -> str:
        return self.name
