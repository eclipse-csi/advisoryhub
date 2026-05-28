"""Eclipse Foundation Projects and their security teams."""

from __future__ import annotations

import uuid

from django.contrib.auth.models import Group
from django.core.validators import RegexValidator
from django.db import models

PMI_ID_VALIDATOR = RegexValidator(
    regex=r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$",
    message=(
        "Must be a valid Eclipse Foundation PMI project id "
        "(lowercase letters, digits, '.', '-', '_'; e.g. 'technology.jetty')."
    ),
)


class Project(models.Model):
    """An Eclipse Foundation project for which advisories may be authored.

    The primary key is a UUID so that downstream references stay stable
    even if the human-readable :attr:`slug` (the Eclipse Foundation PMI
    project id, e.g. ``technology.jetty``) is renamed.

    The ``security_team`` is a Django :class:`Group`; users join the team by
    being members of that group (typically populated from OIDC claims).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    slug = models.CharField(
        max_length=100,
        unique=True,
        validators=[PMI_ID_VALIDATOR],
        help_text="Eclipse Foundation PMI project id (e.g. 'technology.jetty').",
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    homepage_url = models.URLField(blank=True)
    security_team = models.ForeignKey(
        Group,
        on_delete=models.PROTECT,
        related_name="projects_secured",
        help_text="Group whose members are the project's security team.",
    )
    is_mature_publisher = models.BooleanField(
        default=False,
        help_text=(
            "If true, members of the security team can publish advisories without top-level review."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)

    # PMI mirror state. ``last_pmi_sync_at`` is null until the first beat
    # run (or manual refresh) lands. ``last_pmi_sync_error`` carries the
    # redacted error message from the most recent *failed* sync, kept
    # around so the project page can surface a "stale" banner; cleared
    # on the next successful sync.
    last_pmi_sync_at = models.DateTimeField(null=True, blank=True)
    last_pmi_sync_error = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def is_security_team_member(self, user) -> bool:
        if not user.is_authenticated:
            return False
        return user.groups.filter(pk=self.security_team_id).exists()


class ProjectGitHubRepository(models.Model):
    """A GitHub repo associated with a Project, mirrored from PMI.

    PMI (projects.eclipse.org) is the source-of-truth for project↔repo
    mapping. AdvisoryHub mirrors that mapping locally so GHSA sync runs
    don't have to query PMI on every call. Rows that disappear from PMI
    are *soft-removed* (``soft_removed_at`` set) rather than deleted, so
    historical GHSA-linked advisories that still reference the repo keep
    a valid lookup path.
    """

    project = models.ForeignKey(
        Project, on_delete=models.PROTECT, related_name="github_repositories"
    )
    owner = models.CharField(max_length=100)
    name = models.CharField(max_length=200)
    last_seen_in_pmi_at = models.DateTimeField()
    soft_removed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["project", "owner", "name"],
                name="project_github_repo_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["owner", "name"]),
            models.Index(fields=["project", "soft_removed_at"]),
        ]
        ordering = ["owner", "name"]

    def __str__(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def is_active(self) -> bool:
        return self.soft_removed_at is None
