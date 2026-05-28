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
