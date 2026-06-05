"""Notification-related models.

:class:`AdvisoryNotificationPreference` is a *sparse per-advisory override*
on top of the user's global :class:`accounts.models.NotificationPreference`.
A row exists only when the user has explicitly customized notifications for
that specific advisory:

* Each lifecycle-event field is a nullable ``BooleanField`` — ``None``
  means "inherit the global setting"; ``True``/``False`` override it.
* ``comments_level`` uses an empty-string sentinel for "inherit" since
  Django convention discourages ``null`` on ``CharField``.

When every field is back to its "inherit" sentinel the row is deleted.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models

from accounts.models import CommentLevel


class AdvisoryNotificationPreference(models.Model):
    """Per-user × per-advisory override of notification settings."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="advisory_notification_preferences",
    )
    advisory = models.ForeignKey(
        "advisories.Advisory",
        on_delete=models.CASCADE,
        related_name="notification_preferences",
    )
    on_advisory_submitted_for_review = models.BooleanField(null=True, blank=True, default=None)
    on_advisory_published = models.BooleanField(null=True, blank=True, default=None)
    on_publication_export_status = models.BooleanField(null=True, blank=True, default=None)
    comments_level = models.CharField(
        max_length=16,
        choices=CommentLevel.choices,
        blank=True,
        default="",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("user", "advisory")]
        indexes = [models.Index(fields=["advisory"], name="adv_notif_pref_adv_idx")]

    LIFECYCLE_FIELDS = (
        "on_advisory_submitted_for_review",
        "on_advisory_published",
        "on_publication_export_status",
    )

    def __str__(self) -> str:
        return f"{self.user.email} prefs for {self.advisory.advisory_id}"

    def is_empty(self) -> bool:
        """True when every field is at its "inherit" sentinel — the row
        contributes nothing and the caller should delete it."""
        if self.comments_level:
            return False
        return all(getattr(self, f) is None for f in self.LIFECYCLE_FIELDS)


class NotificationKind(models.TextChoices):
    """Kinds of delivered notification.

    The values mirror the email *event* strings emitted by
    :mod:`notifications.tasks`, so a row's kind is unambiguous at the send
    site. The seven triage events collapse into a single ``TRIAGE`` kind — the
    stored ``subject`` already carries the specifics.
    """

    ADVISORY_CREATED = "advisory_created", "Advisory created"
    SUBMITTED_FOR_REVIEW = "advisory_submitted_for_review", "Submitted for review"
    PUBLISHED = "advisory_published", "Published"
    PUBLICATION_EXPORT_STATUS = "publication_export_status", "Publication status"
    COMMENT = "comment", "New comment"
    MENTION = "mention", "Mention"
    TRIAGE = "triage", "Triage activity"


class Notification(models.Model):
    """A single notification delivered to a user by email.

    One row is created per recipient *after* the matching email is sent (see
    :func:`notifications.services.record_delivery`), giving the user an in-app
    inbox of what they were told and a mutable ``read_at`` flag.

    Only a denormalized ``subject`` plus a short ``summary`` are stored — never
    the comment body — so a later access downgrade cannot leak internal-comment
    content through the inbox. Invitations are intentionally *not* represented
    here: they are sent to a bare email address that may have no ``User`` row.
    """

    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    advisory = models.ForeignKey(
        "advisories.Advisory",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    kind = models.CharField(max_length=40, choices=NotificationKind.choices)
    # Mirrors AuditLogEntry.comment_id — the comment a comment/mention row
    # concerns, without a hard FK (comments may be redacted independently).
    comment_id = models.BigIntegerField(null=True, blank=True)
    subject = models.CharField(max_length=255)
    summary = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)

    # View-only display flag (not a DB field): the inbox view sets this False
    # when the recipient can no longer see the advisory, so the row renders
    # without a link. Defaults True so every render path has a value.
    visible: bool = True

    class Meta:
        # No unique_together: a user legitimately receives many notifications
        # for the same advisory/kind over time (every comment is its own row).
        ordering = ["-created_at"]
        indexes = [
            # Unread-count badge + "unread" filter.
            models.Index(fields=["recipient", "read_at"], name="notif_recipient_read_idx"),
            # Paginated inbox ordering.
            models.Index(fields=["recipient", "-created_at"], name="notif_recipient_created_idx"),
            # Auto-read sweep when a viewer opens an advisory's detail page.
            models.Index(
                fields=["recipient", "advisory", "read_at"], name="notif_recipient_adv_idx"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.kind} → {self.recipient.email}"
