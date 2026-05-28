"""Audit log browser — paginated, with multi-faceted filters.

Filters (all optional, ANDed together):

* ``action`` (repeatable) — one or more :class:`audit.models.Action` values.
* ``actor`` — substring match on the actor's email, display name, or
  first/last name. The literal ``system`` matches entries with no actor
  (``actor IS NULL``).
* ``advisory`` — substring match on ``Advisory.advisory_id``.
* ``since`` / ``until`` — ISO dates. ``until`` is inclusive of the whole
  day (implemented via ``__lt next-day``). A ``preset`` of ``24h`` /
  ``7d`` / ``30d`` fills ``since`` server-side when ``since`` is blank;
  an explicit ``since`` always wins over the preset.
* ``q`` — free-text substring search across ``metadata``,
  ``previous_value``, and ``new_value`` JSON columns.

Pagination links must preserve the (potentially multi-valued) filter
state, so the view builds a ``filters_querystring`` and the page partial
uses it when present.
"""

from __future__ import annotations

import datetime as _dt
from urllib.parse import urlencode

from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import render
from django.utils import timezone

from audit.models import Action, AuditLogEntry

from .base import admin_required

PER_PAGE = 50

PRESET_DELTAS: dict[str, _dt.timedelta] = {
    "24h": _dt.timedelta(hours=24),
    "7d": _dt.timedelta(days=7),
    "30d": _dt.timedelta(days=30),
}


def _parse_date(value: str) -> _dt.date | None:
    if not value:
        return None
    try:
        return _dt.date.fromisoformat(value)
    except ValueError:
        return None


@admin_required
def audit(request):
    valid_actions = set(Action.values)
    selected_actions = [a for a in request.GET.getlist("action") if a in valid_actions]
    selected_actor = (request.GET.get("actor") or "").strip()
    selected_advisory = (request.GET.get("advisory") or "").strip()
    selected_since_raw = (request.GET.get("since") or "").strip()
    selected_until_raw = (request.GET.get("until") or "").strip()
    selected_preset = (request.GET.get("preset") or "").strip()
    if selected_preset not in PRESET_DELTAS:
        selected_preset = ""
    selected_q = (request.GET.get("q") or "").strip()[:200]

    qs = AuditLogEntry.objects.select_related("actor", "advisory").order_by("-created_at")

    if selected_actions:
        qs = qs.filter(action__in=selected_actions)

    if selected_actor:
        if selected_actor.lower() == "system":
            qs = qs.filter(actor__isnull=True)
        else:
            qs = qs.filter(
                Q(actor__email__icontains=selected_actor)
                | Q(actor__display_name__icontains=selected_actor)
                | Q(actor__first_name__icontains=selected_actor)
                | Q(actor__last_name__icontains=selected_actor)
            )

    if selected_advisory:
        qs = qs.filter(advisory__advisory_id__icontains=selected_advisory)

    since_date = _parse_date(selected_since_raw)
    until_date = _parse_date(selected_until_raw)

    if since_date is None and selected_preset:
        since_dt = timezone.now() - PRESET_DELTAS[selected_preset]
        qs = qs.filter(created_at__gte=since_dt)
    elif since_date is not None:
        qs = qs.filter(
            created_at__gte=timezone.make_aware(_dt.datetime.combine(since_date, _dt.time.min))
        )

    if until_date is not None:
        next_day = until_date + _dt.timedelta(days=1)
        qs = qs.filter(
            created_at__lt=timezone.make_aware(_dt.datetime.combine(next_day, _dt.time.min))
        )

    if selected_q:
        qs = qs.filter(
            Q(metadata__icontains=selected_q)
            | Q(previous_value__icontains=selected_q)
            | Q(new_value__icontains=selected_q)
        )

    page = Paginator(qs, PER_PAGE).get_page(request.GET.get("page"))

    filters_pairs: list[tuple[str, str]] = []
    for value in selected_actions:
        filters_pairs.append(("action", value))
    if selected_actor:
        filters_pairs.append(("actor", selected_actor))
    if selected_advisory:
        filters_pairs.append(("advisory", selected_advisory))
    # Date filters: prefer explicit since/until in the querystring; fall
    # back to the preset only when no explicit since is set.
    if since_date is not None:
        filters_pairs.append(("since", since_date.isoformat()))
    elif selected_preset:
        filters_pairs.append(("preset", selected_preset))
    if until_date is not None:
        filters_pairs.append(("until", until_date.isoformat()))
    if selected_q:
        filters_pairs.append(("q", selected_q))
    filters_querystring = urlencode(filters_pairs)

    any_filter_active = bool(
        selected_actions
        or selected_actor
        or selected_advisory
        or selected_preset
        or since_date
        or until_date
        or selected_q
    )

    return render(
        request,
        "admin_console/audit.html",
        {
            "page": page,
            "action_choices": Action.choices,
            "selected_actions": set(selected_actions),
            "selected_actor": selected_actor,
            "selected_advisory": selected_advisory,
            "selected_since": since_date.isoformat() if since_date else "",
            "selected_until": until_date.isoformat() if until_date else "",
            "selected_preset": selected_preset,
            "selected_q": selected_q,
            "filters_querystring": filters_querystring,
            "any_filter_active": any_filter_active,
            "admin_section": "audit",
        },
    )
