"""Comments on advisories.

Comments are stored as raw markdown in :attr:`AdvisoryComment.body`. Rendered
HTML is generated on demand via :func:`comments.services.render_markdown`,
which runs the body through markdown-it-py and a strict nh3 allowlist.
We never store rendered HTML — re-rendering keeps the sanitizer rules in one
place and lets us tighten them retroactively.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models


class AdvisoryComment(models.Model):
    """A comment on an advisory.

    Comments are never published or disclosed externally — nothing in the
    thread reaches the exported OSV/CSAF or the public advisory website. At
    most, a comment (``is_internal=False``) is visible to anyone with viewer+
    access to the advisory *inside AdvisoryHub*; an internal comment
    (``is_internal=True``) is further restricted to collaborators and owners.
    """

    advisory = models.ForeignKey(
        "advisories.Advisory", on_delete=models.CASCADE, related_name="comments"
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="comments",
    )
    body = models.TextField()
    is_internal = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Visible only to collaborators and owners. Fixed at creation.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    edited_at = models.DateTimeField(null=True, blank=True)
    redacted_at = models.DateTimeField(null=True, blank=True)
    redacted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["advisory", "created_at"]),
            models.Index(fields=["advisory", "is_internal", "created_at"]),
        ]

    def __str__(self) -> str:
        author = self.author.email if self.author else "system"
        return f"comment by {author} on {self.advisory_id}"

    @property
    def is_redacted(self) -> bool:
        return self.redacted_at is not None

    def visible_body(self) -> str:
        """Body to expose to viewers — empty when redacted."""
        return "" if self.is_redacted else self.body


class CommentVersion(models.Model):
    """Append-only revision history for :class:`AdvisoryComment`.

    One row per body state: ``version=1`` is the original creation, each
    subsequent edit appends a new row. The latest row's ``body`` always
    equals the parent comment's current ``body``. Rows are immutable —
    ``save()`` on an existing row and ``delete()`` both raise, mirroring
    :class:`advisories.models.AdvisoryVersion`.
    """

    comment = models.ForeignKey(AdvisoryComment, on_delete=models.CASCADE, related_name="versions")
    version = models.PositiveIntegerField()
    body = models.TextField()
    editor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["comment", "version"]
        unique_together = [("comment", "version")]
        indexes = [models.Index(fields=["comment", "version"])]

    def __str__(self) -> str:
        return f"v{self.version} of comment {self.comment_id}"

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise PermissionError("CommentVersion is append-only; existing rows cannot be saved.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError("CommentVersion is append-only; deletion not allowed.")
