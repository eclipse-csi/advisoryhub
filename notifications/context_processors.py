"""Template context processors for notifications."""

from __future__ import annotations

from . import services


def unread_notifications(request):
    """Expose the current user's unread-notification count to every template,
    driving the top-nav Inbox badge. Returns 0 for anonymous requests (one
    indexed ``COUNT`` per render via :func:`notifications.services.unread_count`).
    """
    return {"unread_notification_count": services.unread_count(getattr(request, "user", None))}
