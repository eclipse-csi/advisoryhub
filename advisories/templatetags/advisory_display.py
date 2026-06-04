"""Presentation helpers for the advisory detail page.

These filters turn raw JSON-field values into the small bits of CSS class
and icon-name strings the template uses to render badges, chips, and SVG
icons. Validation lives in ``advisories.validators``; here we just bucket
already-validated values into display categories.
"""

from __future__ import annotations

import re
from typing import Any

from django import template

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


# ---------------------------------------------------------------------------
# Credits
# ---------------------------------------------------------------------------

_CREDIT_CLASS = {
    "FINDER": "brand",
    "REPORTER": "brand",
    "ANALYST": "info",
    "COORDINATOR": "info",
    "REMEDIATION_DEVELOPER": "ok",
    "REMEDIATION_REVIEWER": "ok",
    "REMEDIATION_VERIFIER": "ok",
    "TOOL": "neutral",
    "SPONSOR": "warn",
    "OTHER": "neutral",
}


@register.filter(name="credit_class")
def credit_class(ctype: Any) -> str:
    return _CREDIT_CLASS.get(str(ctype or "").upper(), "neutral")


@register.filter(name="credit_icon")
def credit_icon(ctype: Any) -> str:
    return "tool" if str(ctype or "").upper() == "TOOL" else "person"


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

    Published advisories are omitted — they accumulate and drown the active
    working set (triage/draft/dismissed) the rail is for; the full set stays one
    click away on /advisories. The advisory being viewed/edited is always pinned
    (and highlighted) even when it is published, so the rail never hides the page
    you're on.

    ``current`` defaults to the page's ``advisory`` context variable (absent on
    the new-advisory form, where nothing is highlighted).
    """
    from advisories.models import State
    from advisories.permissions import visible_advisories

    request = context.get("request")
    user = getattr(request, "user", None)
    current = current or context.get("advisory")

    if user is None or not user.is_authenticated:
        return {"rail_advisories": [], "rail_current_id": None, "rail_remaining": 0}

    qs = (
        visible_advisories(user)
        .exclude(state=State.PUBLISHED)
        .only("advisory_id", "summary", "state", "review_status", "kind", "modified_at")
        .order_by("-modified_at")
    )
    total = qs.count()
    advisories = list(qs[:_RAIL_LIMIT])
    remaining = max(0, total - len(advisories))

    # Pin the current advisory if it isn't already shown (it's published, or
    # beyond the cap). It's safe to surface — the viewer reached its page, so the
    # access check already passed.
    current_pk = getattr(current, "pk", None)
    if current_pk is not None and not any(a.pk == current_pk for a in advisories):
        advisories.insert(0, current)

    return {
        "rail_advisories": advisories,
        "rail_current_id": getattr(current, "advisory_id", None),
        "rail_remaining": remaining,
    }
