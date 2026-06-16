"""Access-log browser — the retention-managed sibling of the audit browser.

Mirrors :mod:`admin_console.views.audit` but queries
:class:`audit.models.AccessLogEntry` (advisory views + GHSA/PMI chatter). Three
deliberate differences from the ledger browser:

* the action filter offers only :data:`audit.models.EPHEMERAL_ACTIONS`;
* free-text ``q`` searches ``metadata`` only (this table has no
  ``previous_value``/``new_value`` columns);
* with no explicit date filter it defaults to a 7-day window, so the first
  load — and its pagination ``COUNT`` — stay bounded on a high-volume table.
"""

from __future__ import annotations

import datetime as _dt
from urllib.parse import urlencode

from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import render
from django.utils import timezone

from audit.models import EPHEMERAL_ACTIONS, AccessLogEntry, Action

from .audit import PER_PAGE, PRESET_DELTAS, _parse_date
from .base import admin_required

# Only the actions that actually land in the access log, in enum order.
ACTION_CHOICES = [(value, label) for value, label in Action.choices if value in EPHEMERAL_ACTIONS]


@admin_required
def access_log(request):
    valid_actions = set(EPHEMERAL_ACTIONS)
    selected_actions = [a for a in request.GET.getlist("action") if a in valid_actions]
    selected_actor = (request.GET.get("actor") or "").strip()
    selected_advisory = (request.GET.get("advisory") or "").strip()
    selected_since_raw = (request.GET.get("since") or "").strip()
    selected_until_raw = (request.GET.get("until") or "").strip()
    selected_preset = (request.GET.get("preset") or "").strip()
    if selected_preset not in PRESET_DELTAS:
        selected_preset = ""
    selected_q = (request.GET.get("q") or "").strip()[:200]

    since_date = _parse_date(selected_since_raw)
    until_date = _parse_date(selected_until_raw)

    # Whether the user constrained the time span themselves. If not, default to
    # a 7-day window so the unfiltered first page (and its COUNT) stays cheap on
    # this high-volume, retention-bounded table.
    user_filtered_time = bool(selected_preset or since_date or until_date)
    if not user_filtered_time:
        selected_preset = "7d"

    qs = (
        AccessLogEntry.objects.select_related("actor", "advisory")
        .prefetch_related("actor__groups")
        .order_by("-created_at")
    )

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
        # No previous_value/new_value columns here — search metadata only.
        qs = qs.filter(metadata__icontains=selected_q)

    page = Paginator(qs, PER_PAGE).get_page(request.GET.get("page"))

    filters_pairs: list[tuple[str, str]] = []
    for value in selected_actions:
        filters_pairs.append(("action", value))
    if selected_actor:
        filters_pairs.append(("actor", selected_actor))
    if selected_advisory:
        filters_pairs.append(("advisory", selected_advisory))
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
        selected_actions or selected_actor or selected_advisory or selected_q or user_filtered_time
    )

    return render(
        request,
        "admin_console/access_log.html",
        {
            "page": page,
            "action_choices": ACTION_CHOICES,
            "selected_actions": set(selected_actions),
            "selected_actor": selected_actor,
            "selected_advisory": selected_advisory,
            "selected_since": since_date.isoformat() if since_date else "",
            "selected_until": until_date.isoformat() if until_date else "",
            "selected_preset": selected_preset,
            "selected_q": selected_q,
            "filters_querystring": filters_querystring,
            "any_filter_active": any_filter_active,
            "admin_section": "access_log",
        },
    )
