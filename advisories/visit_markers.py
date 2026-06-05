"""Helpers for the "Changed since last visit" / "New" markers on advisory lists.

An advisory is *changed* for a viewer when durable audit activity (edits,
comments, state/review/publication events — but **not** plain views, which are
ephemeral ``AccessLogEntry`` rows, never ``AuditLogEntry``) post-dates the
viewer's last visit to its detail page; it is *new* when the viewer has never
opened it. The viewer's *own* actions are excluded, so editing an advisory does
not self-mark it as changed.

Shared by the advisory list view (:func:`advisories.views.advisory_list`) and
the navigation-rail templatetag (``advisories.templatetags.advisory_display``).
"""

from __future__ import annotations

from django.db.models import DateTimeField, Max, OuterRef, Subquery

from audit.models import AuditLogEntry

from .models import AdvisoryVisit


def annotate_visit_markers(qs, user):
    """Annotate an ``Advisory`` queryset with the two timestamps the marker
    needs: ``last_activity_at`` (newest durable audit row authored by *someone
    other than the viewer*) and ``my_last_visit_at`` (the viewer's last visit).

    Both are index-backed correlated subqueries (``AuditLogEntry`` is indexed on
    ``[advisory, created_at]``; ``AdvisoryVisit`` is unique on ``(user, advisory)``),
    so they evaluate only for the rows actually fetched — annotate *before*
    slicing the page.
    """
    last_activity = (
        AuditLogEntry.objects.filter(advisory=OuterRef("pk"))
        .exclude(actor=user)
        .values("advisory")
        .annotate(m=Max("created_at"))
        .values("m")
    )
    my_visit = AdvisoryVisit.objects.filter(advisory=OuterRef("pk"), user=user).values(
        "last_visited_at"
    )
    return qs.annotate(
        last_activity_at=Subquery(last_activity, output_field=DateTimeField()),
        my_last_visit_at=Subquery(my_visit, output_field=DateTimeField()),
    )


def set_visit_markers(advisories) -> None:
    """Set ``.changed_marker`` ∈ {``"new"``, ``"changed"``, ``""``} on each
    advisory in an already-materialized iterable, from the annotations added by
    :func:`annotate_visit_markers`.

    ``"new"`` = never visited; ``"changed"`` = activity since the last visit;
    ``""`` = up to date.
    """
    for advisory in advisories:
        last_activity_at = getattr(advisory, "last_activity_at", None)
        my_last_visit_at = getattr(advisory, "my_last_visit_at", None)
        if my_last_visit_at is None:
            advisory.changed_marker = "new"
        elif last_activity_at is not None and last_activity_at > my_last_visit_at:
            advisory.changed_marker = "changed"
        else:
            advisory.changed_marker = ""
