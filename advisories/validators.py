"""Field validators for advisory data.

These run from ``Advisory.clean`` and from ``ModelForm.clean_*`` methods.
The shapes broadly mirror the OSV schema fields we accept.
"""

from __future__ import annotations

import re
from typing import Any

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

from .ecosystems import is_valid_ecosystem
from .identifiers import ADVISORY_ID_RE

# The CVE program (and the CVE 5.x record schema's ``cveId`` pattern) require a
# 4-to-19-digit sequence number. Keep this in lock-step with the schema so an
# operator cannot reserve/assign an id that later fails CVE export validation.
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$")
GHSA_ID_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)


def validate_advisory_id(value: str) -> None:
    if not value or not ADVISORY_ID_RE.match(value):
        raise ValidationError(
            "Advisory ID must match ECL-xxxx-xxxx-xxxx using unambiguous chars [23456789cfghjmpqrvwx].",
            code="invalid_advisory_id",
        )


def validate_cve_id(value: str) -> None:
    if not value or not CVE_ID_RE.match(value):
        raise ValidationError("CVE id must look like CVE-YYYY-NNNN (4–19 digit sequence number).")


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


# References surface as a clickable <a href> on the advisory detail page
# (templates/advisories/detail.html) and are exported to the public OSV/CSAF
# site repo, so a ``javascript:`` / ``data:`` / ``vbscript:`` URL stored here
# would be a stored-XSS vector. ``URLValidator`` restricts to the same web-safe
# schemes (http/https/ftp/ftps) the ``ReferenceForm`` URLField already enforces.
_REFERENCE_URL_VALIDATOR = URLValidator()


def is_safe_reference_url(url: Any) -> bool:
    """Return ``True`` iff ``url`` is a valid http/https/ftp(s) URL.

    Shared by ``validate_references`` (which raises) and the GHSA translator
    (which drops), so the scheme allow-list can never drift between the write
    paths. The GHSA import path is the load-bearing caller: it persists via
    ``Advisory.save()`` without ``full_clean()``, so the model validator below
    never runs on imported references — the translator must filter them itself.
    """
    if not isinstance(url, str):
        return False
    try:
        _REFERENCE_URL_VALIDATOR(url)
    except ValidationError:
        return False
    return True


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
        if not is_safe_reference_url(ref["url"]):
            raise ValidationError(
                "each reference url must be a valid http(s) URL.",
                code="invalid_references",
            )
        rtype = ref.get("type", "WEB")
        if rtype not in allowed_types:
            raise ValidationError(
                f"reference type {rtype!r} not one of {sorted(allowed_types)}",
                code="invalid_references",
            )


EVENT_KINDS_ALLOWED = frozenset({"introduced", "fixed", "last_affected", "limit"})

# Package URL (purl) — a loose *shape* check, not a full purl parse: it catches
# the common mistakes (missing ``pkg:`` prefix or type) without rejecting the
# qualifiers/``@version`` some advisories legitimately carry. Kept in lock-step
# with the client pattern in static/advisoryhub-validate.js (KINDS.purl.pattern).
PURL_RE = re.compile(r"^pkg:[A-Za-z0-9.+-]+/\S+$")


def is_valid_purl(value: Any) -> bool:
    """True iff ``value`` looks like a ``pkg:type/name…`` package URL."""
    return isinstance(value, str) and PURL_RE.match(value) is not None


def validate_affected(value: Any) -> None:
    """OSV-style ``affected`` block: list of objects with package + ranges/versions."""
    if value is None:
        return
    if not isinstance(value, list):
        raise ValidationError("affected must be a list.", code="invalid_affected")
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise ValidationError("each affected entry must be an object.", code="invalid_affected")
        pkg = entry.get("package")
        if not isinstance(pkg, dict) or not pkg.get("name"):
            raise ValidationError("each affected entry needs package.name", code="invalid_affected")
        ecosystem = pkg.get("ecosystem")
        if not ecosystem:
            raise ValidationError(
                f"affected[{index}]: package.ecosystem is required",
                code="invalid_affected",
            )
        if not is_valid_ecosystem(ecosystem):
            raise ValidationError(
                f"affected[{index}]: ecosystem {ecosystem!r} is not a recognised OSV "
                "ecosystem (e.g. Maven, npm, PyPI — optionally with a ':' suffix like Debian:11)",
                code="invalid_affected",
            )
        purl = pkg.get("purl")
        if purl and not is_valid_purl(purl):
            raise ValidationError(
                f"affected[{index}]: purl {purl!r} is not a valid package URL "
                "(expected pkg:type/name, e.g. pkg:maven/org.example/lib)",
                code="invalid_affected",
            )
        ranges = entry.get("ranges") or []
        versions = entry.get("versions") or []
        if not isinstance(ranges, list) or not isinstance(versions, list):
            raise ValidationError(
                f"affected[{index}]: ranges and versions must be lists",
                code="invalid_affected",
            )
        if not ranges and not versions:
            raise ValidationError(
                "each affected entry needs at least one of ranges or versions",
                code="invalid_affected",
            )
        for r in ranges:
            if not isinstance(r, dict) or not r.get("type"):
                raise ValidationError("range needs a type", code="invalid_affected")
            events = r.get("events") or []
            if not isinstance(events, list):
                raise ValidationError("range events must be a list", code="invalid_affected")
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
                if not isinstance(kind, str) or kind not in EVENT_KINDS_ALLOWED:
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
