"""Presentation helpers for the advisory detail page.

These filters turn raw JSON-field values into the small bits of CSS class
and icon-name strings the template uses to render badges, chips, and SVG
icons. Validation lives in ``advisories.validators``; here we just bucket
already-validated values into display categories.
"""

from __future__ import annotations

import re
from typing import Any

from cvss import CVSS2, CVSS3, CVSS4
from django import template
from django.utils.timesince import timesince as django_timesince

from advisories.cwes import name_for as cwe_name_for

register = template.Library()


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

_UBUNTU_LEVELS = {"critical", "high", "medium", "low", "negligible"}

# CVSS scores may arrive as a plain numeric ("9.8"), a bare vector
# ("CVSS:3.1/AV:N/..."), or a vector with the numeric score appended.
# Strip a leading ``CVSS:N.N`` prefix first so we don't mistake the spec
# version for a severity, then look for the first standalone number.
_CVSS_PREFIX_RE = re.compile(r"^\s*CVSS:\d+(?:\.\d+)?")
_FIRST_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")


def _cvss_level(score: str) -> str:
    text = _CVSS_PREFIX_RE.sub("", score or "")
    # If anything remains, it's a vector (e.g. "/AV:N/AC:L/..."). Vector
    # letters like "C:H" contain no decimal numbers, so we'll only match
    # if a numeric severity was actually appended.
    match = _FIRST_NUMBER_RE.search(text)
    if not match:
        return "none"
    try:
        value = float(match.group(0))
    except ValueError:
        return "none"
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0.0:
        return "low"
    return "none"


@register.filter(name="severity_level")
def severity_level(entry: Any) -> str:
    """Return one of: critical | high | medium | low | negligible | none."""
    if not isinstance(entry, dict):
        return "none"
    stype = entry.get("type") or ""
    score = entry.get("score") or ""
    if stype == "Ubuntu":
        return score if score in _UBUNTU_LEVELS else "none"
    return _cvss_level(score)


def _level_from_score(value: float) -> str:
    """Bucket a numeric CVSS base score into the qualitative level (matches the
    ``sev-level-*`` colour classes)."""
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0.0:
        return "low"
    return "none"


_CVSS_VERSION_LABEL = {"CVSS_V2": "CVSS 2.0", "CVSS_V3": "CVSS 3.1", "CVSS_V4": "CVSS 4.0"}


@register.filter(name="cvss_display")
def cvss_display(entry: Any) -> dict[str, str] | None:
    """Compact one-line CVSS view: ``{version, score, level, vector}`` (or None).

    Derives the numeric base score and qualitative level from the stored vector
    via the ``cvss`` library — the same engine the publication CVE builder uses
    (``publication.cve``) — so the detail page needs no client-side CVSS maths.
    Returns ``None`` for a non-dict / empty entry. An unparseable vector (or an
    ``Ubuntu`` entry, which carries a level word rather than a vector) still
    surfaces with an empty ``score`` so the severity is never silently dropped.
    """
    if not isinstance(entry, dict):
        return None
    stype = entry.get("type") or ""
    vector = (entry.get("score") or "").strip()
    if not vector:
        return None
    if stype == "Ubuntu":
        # Ubuntu carries a bare severity word ("high", …), not a CVSS vector —
        # show it verbatim with no version descriptor.
        word = vector.lower()
        return {
            "version": "",
            "score": vector,
            "level": word if word in _UBUNTU_LEVELS else "none",
            "vector": vector,
        }
    try:
        if stype == "CVSS_V2":
            value = float(CVSS2(vector).base_score)
            version = "CVSS 2.0"
        elif stype == "CVSS_V3":
            c3 = CVSS3(vector)
            value = float(c3.base_score)
            version = "CVSS 3.0" if c3.as_json().get("version") == "3.0" else "CVSS 3.1"
        elif stype == "CVSS_V4":
            value = float(CVSS4(vector).base_score)
            version = "CVSS 4.0"
        else:
            return {"version": stype, "score": "", "level": "none", "vector": vector}
    except Exception:
        return {
            "version": _CVSS_VERSION_LABEL.get(stype, stype or "?"),
            "score": "",
            "level": "none",
            "vector": vector,
        }
    return {
        "version": version,
        "score": f"{value:.1f}",
        "level": _level_from_score(value),
        "vector": vector,
    }


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------

_REFERENCE_CLASS = {
    "ADVISORY": "danger",
    "REPORT": "danger",
    "FIX": "ok",
    "PACKAGE": "info",
    "GIT": "brand",
    "INTRODUCED": "brand",
    "DETECTION": "warn",
    "EVIDENCE": "warn",
    "ARTICLE": "neutral",
    "DISCUSSION": "neutral",
    "WEB": "neutral",
}

_REFERENCE_ICON = {
    "ADVISORY": "shield",
    "REPORT": "bell",
    "FIX": "wrench",
    "PACKAGE": "package",
    "GIT": "code-branch",
    "INTRODUCED": "bug",
    "DETECTION": "eye",
    "EVIDENCE": "magnifying-glass",
    "ARTICLE": "document",
    "DISCUSSION": "chat-bubble",
    "WEB": "globe",
}


@register.filter(name="reference_class")
def reference_class(rtype: Any) -> str:
    return _REFERENCE_CLASS.get(str(rtype or "").upper(), "neutral")


@register.filter(name="reference_icon")
def reference_icon(rtype: Any) -> str:
    return _REFERENCE_ICON.get(str(rtype or "").upper(), "globe")


# ---------------------------------------------------------------------------
# Affected ranges
# ---------------------------------------------------------------------------

_EVENT_CLASS = {
    "introduced": "warn",
    "fixed": "ok",
    "limit": "danger",
    "last_affected": "danger",
}


@register.filter(name="event_kind_class")
def event_kind_class(kind: Any) -> str:
    return _EVENT_CLASS.get(str(kind or "").lower(), "neutral")


@register.filter(name="event_pairs")
def event_pairs(events: Any) -> list[dict[str, str]]:
    """Flatten OSV single-key event dicts into ``{"kind", "value"}`` pairs.

    Events are stored in the OSV shape — one key per dict, e.g.
    ``{"introduced": "1.0.0"}`` (see ``advisories.form_assembly``). The detail
    template needs the kind and version split apart to render each event chip,
    so unpack ``items()`` here, mirroring
    ``form_assembly._affected_events_initial``. Non-dict entries are skipped.
    """
    out: list[dict[str, str]] = []
    for ev in events or []:
        if isinstance(ev, dict):
            for kind, value in ev.items():
                out.append({"kind": kind, "value": value})
    return out


# ---------------------------------------------------------------------------
# CWE
# ---------------------------------------------------------------------------


@register.filter(name="cwe_name")
def cwe_name(cwe_id: Any) -> str:
    """Return the human-readable CWE name, or an empty string."""
    if not cwe_id:
        return ""
    return cwe_name_for(str(cwe_id)) or ""


# ---------------------------------------------------------------------------
# Misc small helpers
# ---------------------------------------------------------------------------


@register.filter(name="humanize_type")
def humanize_type(value: Any) -> str:
    """Turn ``REMEDIATION_DEVELOPER`` into ``Remediation developer``."""
    if not value:
        return ""
    return str(value).replace("_", " ").capitalize()


@register.filter(name="coarse_timesince")
def coarse_timesince(value: Any) -> str:
    """Time since ``value`` to the single largest unit, e.g. ``"3 days"``.

    Django's built-in ``timesince`` shows two units (``"3 days, 4 hours"``);
    we pin ``depth=1`` so the list/inbox age columns stay scannable — minutes
    drop once it's been an hour, hours drop once it's been a day, and so on.
    Callers append " ago" in the template; the exact datetime stays in a
    ``title`` tooltip. Returns "" for a falsy value, matching the built-in.
    """
    if not value:
        return ""
    try:
        return django_timesince(value, depth=1)
    except (ValueError, TypeError):
        return ""


# ---------------------------------------------------------------------------
# Advisory navigation rail
# ---------------------------------------------------------------------------

# Cap the dense left rail so a user reachable to thousands of advisories (an
# admin) doesn't render thousands of rows on every detail/edit page. The full
# set is always one click away on /advisories; mirror its max page_size.
_RAIL_LIMIT = 200


@register.inclusion_tag("advisories/_rail.html", takes_context=True)
def advisory_rail(context: Any, current: Any = None) -> dict[str, Any]:
    """Render the dense left-hand rail of advisories the viewer can reach.

    Shared by the advisory detail and edit pages so a user can jump between
    advisories without going back to the list. Visibility uses the same
    server-side source of truth as the list view
    (``advisories.permissions.visible_advisories``), so the rail can never
    surface an advisory the viewer couldn't already reach (INV-AUTH-1).

    Published and dismissed advisories are omitted — they accumulate and drown
    the active working set (triage/draft) the rail is for; the full set stays one
    click away on /advisories. The advisory being viewed/edited is always pinned
    (and highlighted) even when it is published or dismissed, so the rail never
    hides the page you're on.

    ``current`` defaults to the page's ``advisory`` context variable (absent on
    the new-advisory form, where nothing is highlighted).
    """
    from advisories.models import State
    from advisories.permissions import visible_advisories
    from advisories.visit_markers import annotate_visit_markers, set_visit_markers

    request = context.get("request")
    user = getattr(request, "user", None)
    current = current or context.get("advisory")

    if user is None or not user.is_authenticated:
        return {"rail_advisories": [], "rail_current_id": None, "rail_remaining": 0}

    qs = (
        visible_advisories(user)
        .exclude(state__in=[State.PUBLISHED, State.DISMISSED])
        .only("advisory_id", "summary", "state", "review_status", "kind", "modified_at")
        .order_by("-modified_at")
    )
    total = qs.count()
    advisories = list(annotate_visit_markers(qs, user)[:_RAIL_LIMIT])
    set_visit_markers(advisories)
    remaining = max(0, total - len(advisories))

    # Pin the current advisory if it isn't already shown (it's published or
    # dismissed, or beyond the cap). It's safe to surface — the viewer reached
    # its page, so the access check already passed. The page you're on never
    # carries a marker (the visit was just stamped), and the pinned instance
    # has no annotation, so clear it explicitly.
    current_pk = getattr(current, "pk", None)
    if current_pk is not None and not any(a.pk == current_pk for a in advisories):
        current.changed_marker = ""
        advisories.insert(0, current)

    return {
        "rail_advisories": advisories,
        "rail_current_id": getattr(current, "advisory_id", None),
        "rail_remaining": remaining,
    }
