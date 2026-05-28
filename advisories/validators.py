"""Field validators for advisory data.

These run from ``Advisory.clean`` and from ``ModelForm.clean_*`` methods.
The shapes broadly mirror the OSV schema fields we accept.
"""

from __future__ import annotations

import re
from typing import Any

from django.core.exceptions import ValidationError

from .identifiers import ADVISORY_ID_RE

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{1,10}$")
GHSA_ID_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)


def validate_advisory_id(value: str) -> None:
    if not value or not ADVISORY_ID_RE.match(value):
        raise ValidationError(
            "Advisory ID must match ECL-xxxx-xxxx-xxxx using unambiguous chars [23456789cfghjmpqrvwx].",
            code="invalid_advisory_id",
        )


def validate_cve_id(value: str) -> None:
    if not value or not CVE_ID_RE.match(value):
        raise ValidationError("CVE id must look like CVE-YYYY-NNNN.")


def validate_ghsa_id(value: str) -> None:
    if not value or not GHSA_ID_RE.match(value):
        raise ValidationError(
            "GHSA id must look like GHSA-xxxx-xxxx-xxxx (alphanumeric).",
            code="invalid_ghsa_id",
        )


def validate_aliases(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise ValidationError("aliases must be a list of strings.", code="invalid_aliases")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValidationError(
                "aliases entries must be non-empty strings.", code="invalid_aliases"
            )


def validate_references(value: Any) -> None:
    """OSV-style references: list of {type, url}."""
    if value is None:
        return
    if not isinstance(value, list):
        raise ValidationError("references must be a list.", code="invalid_references")
    allowed_types = {
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
    }
    for ref in value:
        if not isinstance(ref, dict):
            raise ValidationError("each reference must be an object.", code="invalid_references")
        if "url" not in ref or not isinstance(ref["url"], str) or not ref["url"]:
            raise ValidationError(
                "each reference needs a non-empty url.", code="invalid_references"
            )
        rtype = ref.get("type", "WEB")
        if rtype not in allowed_types:
            raise ValidationError(
                f"reference type {rtype!r} not one of {sorted(allowed_types)}",
                code="invalid_references",
            )


EVENT_KINDS_ALLOWED = frozenset({"introduced", "fixed", "last_affected", "limit"})


def validate_affected(value: Any) -> None:
    """OSV-style ``affected`` block: list of objects with package + ranges/versions."""
    if value is None:
        return
    if not isinstance(value, list):
        raise ValidationError("affected must be a list.", code="invalid_affected")
    for entry in value:
        if not isinstance(entry, dict):
            raise ValidationError("each affected entry must be an object.", code="invalid_affected")
        pkg = entry.get("package")
        if not isinstance(pkg, dict) or not pkg.get("name"):
            raise ValidationError("each affected entry needs package.name", code="invalid_affected")
        ranges = entry.get("ranges") or []
        versions = entry.get("versions") or []
        if not ranges and not versions:
            raise ValidationError(
                "each affected entry needs at least one of ranges or versions",
                code="invalid_affected",
            )
        for r in ranges:
            if not isinstance(r, dict) or not r.get("type"):
                raise ValidationError("range needs a type", code="invalid_affected")
            events = r.get("events") or []
            if not events:
                raise ValidationError("range needs at least one event", code="invalid_affected")
            kinds: list[str] = []
            for ev in events:
                if not isinstance(ev, dict) or len(ev) != 1:
                    raise ValidationError(
                        "each event must be an object with exactly one of "
                        "introduced, fixed, last_affected, or limit",
                        code="invalid_affected",
                    )
                ((kind, version),) = ev.items()
                if kind not in EVENT_KINDS_ALLOWED:
                    raise ValidationError(
                        f"event kind {kind!r} must be one of {sorted(EVENT_KINDS_ALLOWED)}",
                        code="invalid_affected",
                    )
                if not isinstance(version, str) or not version.strip():
                    raise ValidationError(
                        f"event {kind!r} needs a non-empty version string",
                        code="invalid_affected",
                    )
                kinds.append(kind)
            if "introduced" not in kinds:
                raise ValidationError(
                    "range needs at least one 'introduced' event",
                    code="invalid_affected",
                )
            if "fixed" in kinds and "last_affected" in kinds:
                raise ValidationError(
                    "'fixed' and 'last_affected' events are mutually exclusive within a range",
                    code="invalid_affected",
                )


def validate_credits(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise ValidationError("credits must be a list.", code="invalid_credits")
    allowed_types = {
        "FINDER",
        "REPORTER",
        "ANALYST",
        "COORDINATOR",
        "REMEDIATION_DEVELOPER",
        "REMEDIATION_REVIEWER",
        "REMEDIATION_VERIFIER",
        "TOOL",
        "SPONSOR",
        "OTHER",
    }
    for credit in value:
        if not isinstance(credit, dict) or not credit.get("name"):
            raise ValidationError("each credit needs a name", code="invalid_credits")
        ctype = credit.get("type")
        if ctype is not None and ctype not in allowed_types:
            raise ValidationError(
                f"credit type {ctype!r} not one of {sorted(allowed_types)}",
                code="invalid_credits",
            )


def validate_severity(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise ValidationError(
            "severity must be a list of {type, score} entries.", code="invalid_severity"
        )
    allowed = {"CVSS_V2", "CVSS_V3", "CVSS_V4", "Ubuntu"}
    ubuntu_scores = {"negligible", "low", "medium", "high", "critical"}
    for entry in value:
        if not isinstance(entry, dict):
            raise ValidationError("each severity entry must be an object.", code="invalid_severity")
        stype = entry.get("type")
        if stype not in allowed:
            raise ValidationError(
                f"severity.type must be one of {sorted(allowed)}", code="invalid_severity"
            )
        score = entry.get("score")
        if not score:
            raise ValidationError("severity.score is required", code="invalid_severity")
        if stype == "Ubuntu" and score not in ubuntu_scores:
            raise ValidationError(
                f"Ubuntu severity.score must be one of {sorted(ubuntu_scores)}",
                code="invalid_severity",
            )


def validate_cwe_ids(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise ValidationError("cwe_ids must be a list of strings", code="invalid_cwe_ids")
    # Imported lazily because the catalog file is large and importing it at
    # module load time would slow `manage.py` invocations that don't touch
    # advisories.
    from .cwes import is_known

    for cwe in value:
        if not isinstance(cwe, str) or not cwe.upper().startswith("CWE-"):
            raise ValidationError("each CWE id must start with 'CWE-'", code="invalid_cwe_ids")
        if not is_known(cwe):
            raise ValidationError(
                f"{cwe} is not a recognised CWE identifier",
                code="invalid_cwe_ids",
            )
