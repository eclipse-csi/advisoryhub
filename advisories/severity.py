"""Canonical severity parsing — shared by the model layer and the templates.

``Advisory.severity`` is a list of OSV ``{type, score}`` entries whose
qualitative level (critical/high/…) and numeric base score are *derived* from
the stored CVSS vector via the ``cvss`` library (the same engine the publication
CVE builder uses, ``publication.cve``). SQL can't parse a CVSS vector, so the
list view can't filter or sort on severity directly; instead, the worst entry's
level + score are denormalised onto ``Advisory.severity_level`` /
``Advisory.severity_score`` at save time (see :meth:`Advisory.save`) via
:func:`effective_severity`.

This module is intentionally free of Django/template imports so it can be used
from ``models.save()``, data migrations, and the
``advisories.templatetags.advisory_display`` filters alike.
"""

from __future__ import annotations

from typing import Any

from cvss import CVSS2, CVSS3, CVSS4

# Ubuntu carries a bare qualitative word rather than a CVSS vector.
UBUNTU_LEVELS = {"critical", "high", "medium", "low", "negligible"}

CVSS_VERSION_LABEL = {"CVSS_V2": "CVSS 2.0", "CVSS_V3": "CVSS 3.1", "CVSS_V4": "CVSS 4.0"}

# The denormalised, stored levels surfaced in the list filter/sort/badge. Ubuntu
# ``negligible`` folds into ``low`` here (see :func:`effective_severity`) so the
# filter dropdown stays to five options; the detail page still renders the
# faithful per-entry level via ``advisory_display.cvss_display``.
SEVERITY_LEVEL_CHOICES = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("none", "Unscored"),
]

# Lifecycle-style rank for the *stored* five-value levels — consumed by the list
# view's severity sort (a ``Case`` annotation, mirroring its ``state_rank``).
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Internal rank including ``negligible`` so the worst entry is picked correctly
# *before* the fold into the five stored levels.
_ENTRY_RANK = {"none": 0, "negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def level_from_score(value: float) -> str:
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


def analyze_entry(entry: Any) -> dict[str, Any] | None:
    """Authoritative per-entry severity view, or ``None`` for an empty/non-dict
    entry.

    Returns ``{version, score, level, vector, value}`` where ``value`` is the
    numeric CVSS base score (``float``) or ``None`` (Ubuntu / unparseable), and
    ``score`` is the display string (``"7.5"``, the Ubuntu word, or ``""``).
    The first four keys are exactly what ``cvss_display`` has always returned,
    so the detail page is unaffected; ``value`` is the extra signal the
    denormalisation needs.
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
            "level": word if word in UBUNTU_LEVELS else "none",
            "vector": vector,
            "value": None,
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
            return {"version": stype, "score": "", "level": "none", "vector": vector, "value": None}
    except Exception:
        return {
            "version": CVSS_VERSION_LABEL.get(stype, stype or "?"),
            "score": "",
            "level": "none",
            "vector": vector,
            "value": None,
        }
    return {
        "version": version,
        "score": f"{value:.1f}",
        "level": level_from_score(value),
        "vector": vector,
        "value": value,
    }


def effective_severity(severity: Any) -> tuple[str, float | None]:
    """Worst entry's ``(level, numeric_score)`` for the denormalised columns.

    Picks the entry maximising ``(level rank, numeric score)`` across the list,
    so an advisory carrying both a high CVSS vector and a low Ubuntu word ranks
    by the CVSS one. Ubuntu ``negligible`` folds into ``low``. Empty / all-none
    severity yields ``("none", None)`` — and a level of ``none`` never carries a
    score, so an unscored row renders an em dash rather than ``0.0``.
    """
    best_level = "none"
    best_value: float | None = None
    best_key = (-1, -1.0)
    for entry in severity or []:
        info = analyze_entry(entry)
        if info is None:
            continue
        level = info["level"]
        value = info["value"]
        key = (_ENTRY_RANK.get(level, 0), value if value is not None else -1.0)
        if key > best_key:
            best_key = key
            best_level = level
            best_value = value
    if best_level == "negligible":
        best_level = "low"
    if best_level == "none":
        best_value = None
    return best_level, best_value
