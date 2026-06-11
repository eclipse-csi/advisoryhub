"""CSAF 2.0 JSON builder (subset).

We produce a CSAF 2.0 ``csaf_security_advisory`` document with the
mandatory document/tracking/publisher/vulnerabilities fields, populated
from a pinned :class:`AdvisoryVersion`. Like OSV, the output is
deterministic for the same inputs.
"""

from __future__ import annotations

import json
import re
from datetime import UTC
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.protocols import Validator

from advisories.models import AdvisoryVersion

CSAF_VERSION = "2.0"
_SCHEMA_PATH = Path(__file__).parent / "schemas" / "csaf.upstream.json"

# CSAF restricts the `cve` field to canonical CVE IDs (4+ digits in the
# numeric part). Aliases that don't match are routed to `ids[]` instead.
_STRICT_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def _format_ts(dt) -> str:
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"


def _validator() -> Validator:
    schema = json.loads(_SCHEMA_PATH.read_text())
    return Draft202012Validator(schema)


def build_csaf(
    version: AdvisoryVersion,
    *,
    publisher_name: str = "Eclipse Foundation",
    publisher_namespace: str = "https://www.eclipse.org/security/",
    current_release_date=None,
    initial_release_date=None,
) -> dict[str, Any]:
    payload = version.payload
    current = _format_ts(current_release_date or version.created_at)
    initial = _format_ts(initial_release_date or version.created_at)
    advisory_id = payload["advisory_id"]

    notes: list[dict[str, str]] = []
    if payload.get("summary"):
        notes.append({"category": "summary", "text": payload["summary"], "title": "Summary"})
    if payload.get("details"):
        notes.append({"category": "description", "text": payload["details"], "title": "Details"})

    references = []
    for ref in payload.get("references", []) or []:
        references.append(
            {
                "category": _csaf_reference_category(ref.get("type", "WEB")),
                "summary": ref.get("type", "reference"),
                "url": ref["url"],
            }
        )

    # Pick the first CVE-shaped alias that matches CSAF's strict CVE regex.
    # Non-conforming entries (e.g. CVE-2026-1) become `ids[]` entries instead
    # so we never emit a CSAF doc rejected by the upstream schema's `cve` field.
    # The EF-assigned CVE is biased to the front so it lands in vuln.cve when
    # present, even if the editor also added another CVE to the aliases list.
    aliases = list(payload.get("aliases") or [])
    if payload.get("assigned_cve_id"):
        aliases.insert(0, payload["assigned_cve_id"])
    cve_id = next((a for a in aliases if _STRICT_CVE_RE.match(a)), None)

    vuln: dict[str, Any] = {
        "title": payload.get("summary") or advisory_id,
    }
    if notes:
        vuln["notes"] = notes
    if references:
        vuln["references"] = references
    if cve_id:
        vuln["cve"] = cve_id
    other_aliases = [a for a in aliases if a != cve_id]
    if other_aliases:
        vuln["ids"] = [
            {"system_name": "AdvisoryHub", "text": a} for a in sorted(set(other_aliases))
        ]

    cwe_ids = payload.get("cwe_ids") or []
    if cwe_ids:
        primary = cwe_ids[0]
        vuln["cwe"] = {"id": primary, "name": primary}

    document = {
        "category": "csaf_security_advisory",
        "csaf_version": CSAF_VERSION,
        "title": payload.get("summary") or advisory_id,
        "publisher": {
            "category": "vendor",
            "name": publisher_name,
            "namespace": publisher_namespace,
        },
        "tracking": {
            "id": advisory_id,
            "current_release_date": current,
            "initial_release_date": initial,
            "status": "final",
            "version": "1",
            "revision_history": [
                {
                    "date": initial,
                    "number": "1",
                    "summary": "Initial publication",
                }
            ],
        },
    }

    out: dict[str, Any] = {
        "document": document,
        "vulnerabilities": [vuln],
    }
    return out


def _csaf_reference_category(osv_type: str) -> str:
    osv_type = (osv_type or "").upper()
    if osv_type == "ADVISORY":
        return "self"
    if osv_type == "FIX":
        return "external"
    return "external"


class CsafValidationError(Exception):
    """Raised when a CSAF document fails schema validation."""


def validate_csaf(document: dict[str, Any]) -> None:
    validator = _validator()
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    if errors:
        msg = "; ".join(f"{list(e.absolute_path)}: {e.message}" for e in errors)
        raise CsafValidationError(msg)


def serialize_csaf(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
