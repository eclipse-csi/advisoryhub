"""OSV JSON builder.

The output is built from an immutable ``AdvisoryVersion.payload`` plus a
small amount of derived metadata (timestamps, schema version). It is
deterministic: same version in → byte-identical JSON out, modulo the
``modified``/``published`` timestamps which default to the version's own
``created_at``.
"""

from __future__ import annotations

import json
from datetime import UTC
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from advisories.models import AdvisoryVersion

OSV_SCHEMA_VERSION = "1.6.0"
_SCHEMA_PATH = Path(__file__).parent / "schemas" / "osv.upstream.json"


def _validator() -> Draft202012Validator:
    schema = json.loads(_SCHEMA_PATH.read_text())
    return Draft202012Validator(schema)


def _format_ts(dt) -> str | None:
    """OSV requires UTC timestamps with a trailing ``Z`` rather than ``+00:00``."""

    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    # millisecond precision, Z suffix
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"


def build_osv(version: AdvisoryVersion, *, modified_at=None, published_at=None) -> dict[str, Any]:
    """Build an OSV JSON dict from a pinned advisory version.

    ``modified_at``/``published_at`` default to the version's ``created_at``
    so the output is deterministic for golden-file tests; the publication
    task overrides them with the advisory's published timestamp at run time.
    """
    payload = version.payload
    advisory = version.advisory
    modified = _format_ts(modified_at or version.created_at)
    published = _format_ts(published_at or version.created_at)

    out: dict[str, Any] = {
        "schema_version": OSV_SCHEMA_VERSION,
        "id": payload["advisory_id"],
        "modified": modified,
        "published": published,
    }
    # The EF-assigned CVE lives on Advisory.assigned_cve_id (a first-class
    # field, not part of the editable aliases formset) and is merged into the
    # OSV alias set here at serialization time.
    aliases = list(payload.get("aliases") or [])
    if payload.get("assigned_cve_id"):
        aliases.append(payload["assigned_cve_id"])
    if aliases:
        out["aliases"] = sorted(set(aliases))
    if payload.get("summary"):
        out["summary"] = payload["summary"]
    if payload.get("details"):
        out["details"] = payload["details"]
    if payload.get("severity"):
        out["severity"] = payload["severity"]
    if payload.get("affected"):
        out["affected"] = payload["affected"]
    if payload.get("references"):
        out["references"] = payload["references"]
    if payload.get("credits"):
        out["credits"] = payload["credits"]
    if payload.get("withdrawn_reason"):
        out["withdrawn"] = modified
    database_specific: dict[str, Any] = {
        "advisoryhub": {
            "project_slug": payload.get("project_slug") or advisory.project.slug,
        },
    }
    if payload.get("cwe_ids"):
        database_specific["cwe_ids"] = payload["cwe_ids"]
    out["database_specific"] = database_specific
    return out


class OsvValidationError(Exception):
    """Raised when an OSV document fails schema validation."""


def validate_osv(document: dict[str, Any]) -> None:
    validator = _validator()
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    if errors:
        msg = "; ".join(f"{list(e.absolute_path)}: {e.message}" for e in errors)
        raise OsvValidationError(msg)


def serialize_osv(document: dict[str, Any]) -> str:
    """Serialize an OSV dict to a deterministic JSON string for committing."""
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
