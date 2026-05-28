"""Service helpers for per-advisory notification preferences."""

from __future__ import annotations

from advisories.models import Advisory

from .models import AdvisoryNotificationPreference


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
