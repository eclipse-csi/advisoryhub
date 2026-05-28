"""Diff helpers for the advisory edit-history log.

Used in three places:

* The history page: render adjacent-version diffs across the full log.
* The review queue: a reviewer needs to see what content was frozen at
  submit time vs. either (a) a previous published version or (b) the
  current live advisory.
* The publish page: an admin re-publishing an edited advisory wants to
  see what changed since the last successful push.

The diff is a list of dicts, one per field, with shape::

    {"field": "summary",
     "kind":  "scalar" | "list",
     "before": ...,
     "after":  ...,
     "added":   [...],   # list-only
     "removed": [...]}   # list-only

It is deliberately *plain data* — the template renders it; we don't
generate HTML in the service layer.
"""

from __future__ import annotations

from typing import Any

from advisories.models import Advisory, AdvisoryVersion

# Fields we ship in the diff. Mirrors the version payload shape.
# ``assigned_cve_id`` is a first-class field, not part of the editable
# ``aliases`` list — it is set/cleared by the CVE workflow and must surface
# in the diff so an admin re-publishing after a CVE reservation sees the
# change.
_SCALAR_FIELDS = ("summary", "details", "withdrawn_reason", "assigned_cve_id")
_LIST_FIELDS = (
    "aliases",
    "references",
    "affected",
    "severity",
    "cwe_ids",
    "credits",
)


def version_diff(before: AdvisoryVersion, after: AdvisoryVersion) -> list[dict[str, Any]]:
    """Diff two versions' frozen payloads."""
    return _diff_payloads(before.payload, after.payload)


def live_vs_version(advisory: Advisory, version: AdvisoryVersion) -> list[dict[str, Any]]:
    """Diff a version against the *current* live advisory state."""
    return _diff_payloads(version.payload, advisory.to_payload())


def _diff_payloads(before: dict, after: dict) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for field in _SCALAR_FIELDS:
        b = before.get(field, "") or ""
        a = after.get(field, "") or ""
        if b == a:
            continue
        rows.append({"field": field, "kind": "scalar", "before": b, "after": a})
    for field in _LIST_FIELDS:
        b = before.get(field) or []
        a = after.get(field) or []
        if _items_equal(b, a):
            continue
        added, removed = _list_added_removed(b, a)
        rows.append(
            {
                "field": field,
                "kind": "list",
                "before": b,
                "after": a,
                "added": added,
                "removed": removed,
            }
        )
    return rows


def _items_equal(a: list, b: list) -> bool:
    """Order-independent equality for the OSV-style list fields."""
    return _normalize(a) == _normalize(b)


def _list_added_removed(before: list, after: list) -> tuple[list, list]:
    bn = _normalize(before)
    an = _normalize(after)
    bset = {_freeze(x) for x in bn}
    aset = {_freeze(x) for x in an}
    added = [_thaw(x) for x in aset - bset]
    removed = [_thaw(x) for x in bset - aset]
    return _sorted_for_display(added), _sorted_for_display(removed)


def _normalize(seq: list) -> list:
    """Stable ordering helper — deep-sorts dict keys without losing values."""
    out = []
    for item in seq:
        if isinstance(item, dict):
            out.append({k: item[k] for k in sorted(item)})
        else:
            out.append(item)
    return out


def _freeze(x):
    if isinstance(x, dict):
        return tuple(sorted((k, _freeze(v)) for k, v in x.items()))
    if isinstance(x, list):
        return tuple(_freeze(v) for v in x)
    return x


def _thaw(x):
    if isinstance(x, tuple) and all(isinstance(p, tuple) and len(p) == 2 for p in x):
        return {k: _thaw(v) for k, v in x}
    if isinstance(x, tuple):
        return [_thaw(v) for v in x]
    return x


def _sorted_for_display(items: list) -> list:
    return sorted(items, key=lambda v: str(v))
