"""SLA metrics dashboard — time-to-first-response and time-to-publish.

Read-only. Renders mean + p95 over trailing periods (last week / month /
3 / 6 / 12 months / all time) plus an optional custom date range and a
per-project filter, each with a period-over-period trend chip, and a
"reverted" tally of intake reports promoted then later dismissed. The
computation and the exact metric definitions live in :mod:`admin_console.stats`.
"""

from __future__ import annotations

import datetime as _dt

from django.shortcuts import render
from django.utils import timezone

from audit.services import pruned_history_floor
from projects.models import Project

from ..stats import build_stats_context, custom_period
from .base import admin_required


def _parse_date(value: str) -> _dt.date | None:
    # Mirrors admin_console.views.audit._parse_date — kept local so this view
    # carries no dependency on the audit browser.
    if not value:
        return None
    try:
        return _dt.date.fromisoformat(value)
    except ValueError:
        return None


@admin_required
def stats(request):
    start_date = _parse_date((request.GET.get("start") or "").strip())
    end_date = _parse_date((request.GET.get("end") or "").strip())

    now = timezone.now()
    custom = None
    # A custom range needs both bounds and a sane order; anything else is
    # ignored gracefully (the predefined periods always render).
    if start_date and end_date and start_date <= end_date:
        start_dt = timezone.make_aware(_dt.datetime.combine(start_date, _dt.time.min))
        # ``until`` is inclusive of the whole day → next-day exclusive upper bound.
        end_dt = timezone.make_aware(
            _dt.datetime.combine(end_date + _dt.timedelta(days=1), _dt.time.min)
        )
        custom = custom_period(start_dt, end_dt)

    # Project scope: validate the slug against the DB; an unknown/blank value
    # falls back to "all projects" (the whole page un-scoped).
    selected_project = (request.GET.get("project") or "").strip()
    if selected_project and not Project.objects.filter(slug=selected_project).exists():
        selected_project = ""

    context = build_stats_context(now, custom=custom, project_slug=selected_project or None)
    context.update(
        {
            "admin_section": "stats",
            "selected_start": start_date.isoformat() if start_date else "",
            "selected_end": end_date.isoformat() if end_date else "",
            "has_custom_range": custom is not None,
            "projects": Project.objects.order_by("name").values_list("slug", "name"),
            "selected_project": selected_project,
            "pruned_history_floor": pruned_history_floor(),
        }
    )
    return render(request, "admin_console/stats.html", context)
