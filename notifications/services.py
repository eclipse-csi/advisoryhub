"""Service helpers for per-advisory notification preferences and the inbox."""

from __future__ import annotations

from django.utils import timezone

from advisories.models import Advisory

from .models import AdvisoryNotificationPreference, Notification


def set_advisory_preference(
    user,
    advisory: Advisory,
    *,
    on_advisory_submitted_for_review: bool | None,
    on_advisory_published: bool | None,
    on_publication_export_status: bool | None,
    comments_level: str,
) -> AdvisoryNotificationPreference | None:
    """Create / update / delete the per-advisory override row.

    ``None`` on a lifecycle field and ``""`` on ``comments_level`` mean
    "inherit the global setting." When *all* fields are at their inherit
    sentinel the row is deleted, keeping the table sparse so the absence
    of a row genuinely means "use the user's global defaults."
    """
    comments_level = comments_level or ""
    all_inherit = (
        on_advisory_submitted_for_review is None
        and on_advisory_published is None
        and on_publication_export_status is None
        and not comments_level
    )
    if all_inherit:
        AdvisoryNotificationPreference.objects.filter(user=user, advisory=advisory).delete()
        return None
    obj, _ = AdvisoryNotificationPreference.objects.update_or_create(
        user=user,
        advisory=advisory,
        defaults={
            "on_advisory_submitted_for_review": on_advisory_submitted_for_review,
            "on_advisory_published": on_advisory_published,
            "on_publication_export_status": on_publication_export_status,
            "comments_level": comments_level,
        },
    )
    return obj


def get_advisory_preference(user, advisory: Advisory) -> AdvisoryNotificationPreference | None:
    if not user or not getattr(user, "is_authenticated", False):
        return None
    return AdvisoryNotificationPreference.objects.filter(user=user, advisory=advisory).first()


# ---------------------------------------------------------------------------
# Inbox: delivered-notification records and read-state
# ---------------------------------------------------------------------------


def record_delivery(
    *,
    recipient,
    advisory,
    kind: str,
    subject: str,
    summary: str = "",
    comment_id: int | None = None,
) -> Notification:
    """Persist one delivered-notification row for a recipient.

    Called by :mod:`notifications.tasks` immediately after a notification email
    is sent, so the inbox mirrors what was actually delivered. ``subject`` and
    ``summary`` are truncated to the column width defensively — the task-built
    subjects are short, but a long advisory id must never raise here.
    """
    return Notification.objects.create(
        recipient=recipient,
        advisory=advisory,
        kind=kind,
        subject=subject[:255],
        summary=summary[:255],
        comment_id=comment_id,
    )


def unread_count(user) -> int:
    """Number of unread notifications for ``user`` (0 for anonymous)."""
    if not user or not getattr(user, "is_authenticated", False):
        return 0
    return Notification.objects.filter(recipient=user, read_at__isnull=True).count()


def mark_all_read(user) -> int:
    """Mark every unread notification for ``user`` read. Returns the count."""
    if not user or not getattr(user, "is_authenticated", False):
        return 0
    return Notification.objects.filter(recipient=user, read_at__isnull=True).update(
        read_at=timezone.now()
    )


def mark_advisory_read(user, advisory) -> int:
    """Mark this user's unread notifications for ``advisory`` read.

    Called when the user opens the advisory's detail page — opening the page a
    notification concerns clears it. A single ``UPDATE`` backed by the
    ``[recipient, advisory, read_at]`` index, so it is cheap to call on every view.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return 0
    return Notification.objects.filter(
        recipient=user, advisory=advisory, read_at__isnull=True
    ).update(read_at=timezone.now())
