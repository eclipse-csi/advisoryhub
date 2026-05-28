"""Translate a GitHub repository-security-advisory payload into Advisory fields.

GHSA is the source-of-truth for content on a GHSA-linked advisory. This
module knows how to read GitHub's REST representation and project it onto
AdvisoryHub's OSV-shaped fields without touching anything else (no DB
writes, no audit calls — that's all in ``services.py``).

The function returns a small :class:`TranslateResult` so the caller can
decide what to do with two distinguished pieces of data:

* ``cve_id_from_ghsa`` — present iff GitHub already records a CVE id on
  the advisory. The caller uses this to detect the AdvisoryHub /
  upstream-GHSA CVE conflict case; the translator itself never writes
  ``Advisory.assigned_cve_id``.
* ``ghsa_state`` — published / draft / triage / closed / withdrawn. The
  caller uses this to gate publication and to fill ``Advisory.ghsa_state``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from advisories.models import GHSA_READONLY_FIELDS, Advisory, GhsaState
from advisories.validators import GHSA_ID_RE


@dataclass
class TranslateResult:
    changed_field_names: list[str] = field(default_factory=list)
    cve_id_from_ghsa: str | None = None
    ghsa_state: str = GhsaState.UNKNOWN


def apply_ghsa_to_advisory(advisory: Advisory, payload: dict) -> TranslateResult:
    """Project a GHSA REST payload onto the advisory's mutable fields.

    Only OSV-shaped fields (see :data:`GHSA_READONLY_FIELDS`) are
    rewritten here. Native-advisory governance fields (project,
    advisory_id, state, dismissed_reason, …) are untouched.

    Returns a :class:`TranslateResult` summarising what changed; the
    caller persists ``advisory`` and decides on side-effects.
    """
    result = TranslateResult()
    changed: list[str] = []

    summary = _trim((payload.get("summary") or "")[:300])
    if summary != advisory.summary:
        advisory.summary = summary
        changed.append("summary")

    description = _trim(payload.get("description") or "")
    if description != advisory.details:
        advisory.details = description
        changed.append("details")

    severity = _translate_severity(payload)
    if severity != advisory.severity:
        advisory.severity = severity
        changed.append("severity")

    cwe_ids = _translate_cwes(payload)
    if cwe_ids != advisory.cwe_ids:
        advisory.cwe_ids = cwe_ids
        changed.append("cwe_ids")

    aliases = _translate_aliases(payload)
    if aliases != advisory.aliases:
        advisory.aliases = aliases
        changed.append("aliases")

    references = _translate_references(payload)
    if references != advisory.references:
        advisory.references = references
        changed.append("references")

    affected = _translate_affected(payload)
    if affected != advisory.affected:
        advisory.affected = affected
        changed.append("affected")

    credits = _translate_credits(payload)
    if credits != advisory.credits:
        advisory.credits = credits
        changed.append("credits")

    # Sanity-check the caller hasn't accidentally extended the
    # synchronised set without updating GHSA_READONLY_FIELDS.
    unexpected = set(changed) - GHSA_READONLY_FIELDS
    assert not unexpected, f"translator wrote outside read-only set: {unexpected}"

    result.changed_field_names = changed
    result.cve_id_from_ghsa = _extract_cve_id(payload)
    result.ghsa_state = _translate_state(payload.get("state"))
    return result


# ---------------------------------------------------------------------------
# Individual field translators. Kept module-private so callers always go
# through ``apply_ghsa_to_advisory`` and we never partially apply the
# translation.
# ---------------------------------------------------------------------------

_CVSS_VECTOR_RE = re.compile(r"^CVSS:(?P<v>[234](?:\.\d+)?)/", re.IGNORECASE)
_UBUNTU_SEVERITY = {"negligible", "low", "medium", "high", "critical"}
_GHSA_STATE_MAP = {
    "draft": GhsaState.DRAFT,
    "triage": GhsaState.TRIAGE,
    "published": GhsaState.PUBLISHED,
    "closed": GhsaState.CLOSED,
    "withdrawn": GhsaState.WITHDRAWN,
}

# GHSA credit types are lowercase. Advisory.credits requires uppercase
# strings that map onto ``advisories.validators.validate_credits``.
_CREDIT_TYPE_MAP = {
    "finder": "FINDER",
    "reporter": "REPORTER",
    "analyst": "ANALYST",
    "coordinator": "COORDINATOR",
    "remediation_developer": "REMEDIATION_DEVELOPER",
    "remediation_reviewer": "REMEDIATION_REVIEWER",
    "remediation_verifier": "REMEDIATION_VERIFIER",
    "tool": "TOOL",
    "sponsor": "SPONSOR",
    "other": "OTHER",
}


def _trim(s: str) -> str:
    return (s or "").strip()


def _translate_state(state: str | None) -> str:
    if not state:
        return GhsaState.UNKNOWN
    return _GHSA_STATE_MAP.get(state.lower(), GhsaState.UNKNOWN)


def _extract_cve_id(payload: dict) -> str | None:
    cve = payload.get("cve_id")
    if isinstance(cve, str) and cve.strip():
        return cve.strip()
    # GitHub also surfaces it via identifiers[]. Tolerate the older shape.
    for ident in payload.get("identifiers") or []:
        if (
            isinstance(ident, dict)
            and (ident.get("type") or "").upper() == "CVE"
            and isinstance(ident.get("value"), str)
            and ident["value"].strip()
        ):
            return ident["value"].strip()
    return None


def _translate_severity(payload: dict) -> list[dict]:
    out: list[dict] = []
    cvss = payload.get("cvss") or {}
    vector = (cvss.get("vector_string") or "").strip()
    if vector:
        m = _CVSS_VECTOR_RE.match(vector)
        if m:
            version = m.group("v")
            if version.startswith("2"):
                stype = "CVSS_V2"
            elif version.startswith("4"):
                stype = "CVSS_V4"
            else:
                stype = "CVSS_V3"
        else:
            stype = "CVSS_V3"
        out.append({"type": stype, "score": vector})
    # No vector but a coarse string severity → fall back to the Ubuntu
    # categorical band; otherwise leave the list empty.
    if not out:
        s = (payload.get("severity") or "").strip().lower()
        if s in _UBUNTU_SEVERITY:
            out.append({"type": "Ubuntu", "score": s})
    return out


def _translate_cwes(payload: dict) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for entry in payload.get("cwes") or []:
        if isinstance(entry, dict):
            cwe = entry.get("cwe_id") or entry.get("id") or ""
        elif isinstance(entry, str):
            cwe = entry
        else:
            cwe = ""
        cwe = cwe.strip()
        if not cwe:
            continue
        if not cwe.upper().startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        cwe = cwe.upper()
        if cwe in seen:
            continue
        seen.add(cwe)
        out.append(cwe)
    return out


def _translate_aliases(payload: dict) -> list[str]:
    """Aliases include the GHSA id itself (so the OSV export advertises
    it as an alias) and any non-CVE identifiers GitHub publishes; we
    deliberately exclude CVE identifiers because ``assigned_cve_id`` is
    AdvisoryHub's own authoritative slot."""
    out: list[str] = []
    seen: set[str] = set()
    ghsa = (payload.get("ghsa_id") or "").strip()
    if ghsa and GHSA_ID_RE.match(ghsa):
        out.append(ghsa)
        seen.add(ghsa)
    for ident in payload.get("identifiers") or []:
        if not isinstance(ident, dict):
            continue
        if (ident.get("type") or "").upper() == "CVE":
            continue
        value = (ident.get("value") or "").strip()
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return out


def _translate_references(payload: dict) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    # The plain ``references`` array is a list of strings.
    for entry in payload.get("references") or []:
        if isinstance(entry, str):
            url = entry.strip()
            rtype = "WEB"
        elif isinstance(entry, dict):
            url = (entry.get("url") or "").strip()
            rtype = (entry.get("type") or "WEB").upper()
        else:
            continue
        if not url or url in seen:
            continue
        seen.add(url)
        if rtype not in {
            "ADVISORY",
            "ARTICLE",
            "DETECTION",
            "DISCUSSION",
            "REPORT",
            "FIX",
            "INTRODUCED",
            "GIT",
            "PACKAGE",
            "EVIDENCE",
            "WEB",
        }:
            rtype = "WEB"
        out.append({"type": rtype, "url": url})
    # Make the GHSA's own HTML URL discoverable as an ADVISORY reference.
    html_url = (payload.get("html_url") or "").strip()
    if html_url and html_url not in seen:
        seen.add(html_url)
        out.append({"type": "ADVISORY", "url": html_url})
    return out


def _translate_credits(payload: dict) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    # Prefer the detailed list when present — it carries the type.
    detailed = payload.get("credits_detailed")
    if detailed:
        for entry in detailed:
            if not isinstance(entry, dict):
                continue
            user = entry.get("user") or {}
            name = (user.get("login") or entry.get("login") or "").strip()
            ctype = _CREDIT_TYPE_MAP.get((entry.get("type") or "").lower(), "OTHER")
            if not name:
                continue
            key = (name, ctype)
            if key in seen:
                continue
            seen.add(key)
            out.append({"name": name, "type": ctype})
        return out
    for entry in payload.get("credits") or []:
        if isinstance(entry, str):
            name = entry.strip()
            ctype = "REPORTER"
        elif isinstance(entry, dict):
            name = (entry.get("login") or entry.get("name") or "").strip()
            ctype = _CREDIT_TYPE_MAP.get((entry.get("type") or "").lower(), "REPORTER")
        else:
            continue
        if not name:
            continue
        key = (name, ctype)
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "type": ctype})
    return out


def _translate_affected(payload: dict) -> list[dict]:
    out: list[dict] = []
    for vuln in payload.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        pkg = vuln.get("package") or {}
        ecosystem = (pkg.get("ecosystem") or "").strip()
        name = (pkg.get("name") or "").strip()
        if not name:
            continue
        entry: dict = {"package": {"name": name}}
        if ecosystem:
            entry["package"]["ecosystem"] = _normalise_ecosystem(ecosystem)
        version_range = (vuln.get("vulnerable_version_range") or "").strip()
        patched = (vuln.get("patched_versions") or "").strip()
        events = _parse_vulnerable_range(version_range, patched)
        if events:
            entry["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
        else:
            # Range couldn't be parsed — preserve the original string as
            # a single-version list so the data isn't lost at export time.
            if version_range:
                entry["versions"] = [version_range]
        out.append(entry)
    return out


# OSV ecosystem identifiers are mostly Title-Case (e.g. ``npm``, ``PyPI``,
# ``Maven``). GHSA gives lowercase. The mapping below covers the common
# cases; anything unknown is forwarded as-is.
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pip": "PyPI",
    "pypi": "PyPI",
    "maven": "Maven",
    "rubygems": "RubyGems",
    "go": "Go",
    "composer": "Packagist",
    "packagist": "Packagist",
    "nuget": "NuGet",
    "rust": "crates.io",
    "cargo": "crates.io",
    "pub": "Pub",
    "swift": "SwiftURL",
    "hex": "Hex",
    "actions": "GitHub Actions",
    "github actions": "GitHub Actions",
}


def _normalise_ecosystem(eco: str) -> str:
    return _ECOSYSTEM_MAP.get(eco.lower(), eco)


_RANGE_OP_RE = re.compile(r"\s*(>=|<=|>|<|=)\s*([^\s,]+)")


def _parse_vulnerable_range(spec: str, patched: str) -> list[dict]:
    """Parse a GHSA ``vulnerable_version_range`` into OSV events.

    GHSA strings look like ``">= 1.0.0, < 1.0.5"`` or ``"< 1.0.5"`` or
    ``"= 1.2.3"``. We translate the common shapes into OSV events
    (``introduced`` / ``fixed`` / ``last_affected``). If we can't make
    sense of it, we return an empty list and the caller falls back to
    storing the raw string.
    """
    events: list[dict] = []
    if not spec:
        # If patched_versions is set we can still express "anything
        # before patched is affected".
        if patched:
            return [{"introduced": "0"}, {"fixed": patched}]
        return events

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    exact: str | None = None
    for op, ver in _RANGE_OP_RE.findall(spec):
        ver = ver.strip().rstrip(",")
        if op == ">=":
            introduced = ver
        elif op == ">":
            # OSV doesn't model strict-greater introductions; treat
            # ``> X`` as ``>= X``. The slight over-approximation is
            # documented in the GHSA itself so consumers see the source.
            introduced = ver
        elif op == "<":
            fixed = ver
        elif op == "<=":
            last_affected = ver
        elif op == "=":
            exact = ver

    if exact and not (introduced or fixed or last_affected):
        # ``= X`` collapses to a single-version match.
        return []
    if introduced is None:
        introduced = "0"
    events.append({"introduced": introduced})
    if fixed:
        events.append({"fixed": fixed})
    elif last_affected:
        events.append({"last_affected": last_affected})
    elif patched:
        events.append({"fixed": patched})
    return events
