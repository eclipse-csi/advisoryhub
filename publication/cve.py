"""CVE Record Format 5.2.0 builder.

Emitted only when an advisory carries an Eclipse-Foundation-assigned CVE
(``Advisory.assigned_cve_id``). Like :mod:`publication.osv` and
:mod:`publication.csaf`, the output is built from the immutable
:class:`~advisories.models.AdvisoryVersion` payload pinned on the
publication task — never from live form data (``INV-VERSION-3``) — and is
deterministic for the same inputs (modulo the timestamps, which default to
the version's ``created_at``).

We produce a ``PUBLISHED`` CVE record with the mandatory CNA container
fields (``providerMetadata``, ``descriptions``, ``affected``,
``references``) plus ``problemTypes`` (from CWE ids), ``metrics`` (CVSS),
``credits`` and a ``title``. Validation against the vendored upstream
schema is strict — any gap raises :class:`CveValidationError` and the
publication task fails (the advisory keeps its prior state per
``INV-LIFECYCLE-3``).

The Eclipse Foundation acts as the assigning CNA, so the record carries
the EF CNA organization UUID in both ``cveMetadata.assignerOrgId`` and
``containers.cna.providerMetadata.orgId``. That UUID is operator-supplied
(``PUB_CVE_ASSIGNER_ORG_ID``); when it is missing we raise
:class:`CveAssignerNotConfigured` rather than emit an invalid record.

CVSS metrics are computed from the stored vector string using the ``cvss``
library (base score + base severity, which the typed ``cvssV3_1`` /
``cvssV4_0`` schema fields require). A vector the library cannot parse is
carried verbatim in an ``other`` metric so the severity is never silently
dropped and the record still validates.
"""

from __future__ import annotations

import json
import re
from datetime import UTC
from functools import lru_cache
from pathlib import Path
from typing import Any

from cvss import CVSS2, CVSS3, CVSS4
from jsonschema import Draft7Validator
from jsonschema.exceptions import best_match
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT4, DRAFT7

from advisories import cwes
from advisories.models import AdvisoryVersion
from advisories.validators import CVE_ID_RE

CVE_DATA_VERSION = "5.2.0"
CVE_DATA_TYPE = "CVE_RECORD"

_SCHEMA_DIR = Path(__file__).parent / "schemas"
_SCHEMA_PATH = _SCHEMA_DIR / "cve.upstream.json"
_CVSS_DIR = _SCHEMA_DIR / "cvss"

# The CVE schema references its CVSS sub-schemas with opaque ``file:`` URIs
# (``file:imports/cvss/cvss-v3.1.json`` …). We resolve those to the vendored
# copies via a ``referencing`` registry; the upstream v2.0 import is a
# draft-04 document while the rest are draft-07, so each is registered with
# its own dialect.
_CVSS_IMPORTS: tuple[tuple[str, str, Any], ...] = (
    ("file:imports/cvss/cvss-v2.0.json", "cvss-v2.0.json", DRAFT4),
    ("file:imports/cvss/cvss-v3.0.json", "cvss-v3.0.json", DRAFT7),
    ("file:imports/cvss/cvss-v3.1.json", "cvss-v3.1.json", DRAFT7),
    ("file:imports/cvss/cvss-v4.0.json", "cvss-v4.0.json", DRAFT7),
)

# OSV ``affected[].package.ecosystem`` → CVE ``affected[].collectionURL``.
# Only the values present in the upstream schema's ``collectionURL``
# examples are mapped; an unknown ecosystem simply omits the package
# coordinates and relies on ``vendor`` + ``product``.
_ECOSYSTEM_COLLECTION_URL: dict[str, str] = {
    "Maven": "https://repo.maven.apache.org/maven2",
    "npm": "https://registry.npmjs.org",
    "PyPI": "https://pypi.python.org",
    "Go": "https://golang.org/pkg",
    "NuGet": "https://nuget.org/packages",
    "RubyGems": "https://rubygems.org",
    "crates.io": "https://crates.io",
    "Packagist": "https://packagist.org",
    "Pub": "https://pub.dev",
    "Hex": "https://repo.hex.pm",
}

# A schema-valid v4 UUID (``definitions.uuidType``). The assigner org id must
# match this, not merely be non-empty, before we emit it into the record.
_UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
)

# versionTypes with a well-defined ordering, so a consumer can reliably decide
# whether a given version falls inside an emitted ``[version, lessThan)`` range.
# Only when *every* emitted range is orderable may we assert a blanket
# ``defaultStatus: "unaffected"`` — otherwise a real affected version could
# fall through to the default and be mislabelled safe.
_ORDERABLE_VERSION_TYPES: frozenset[str] = frozenset({"semver", "maven", "python"})

# OSV ``affected[].package.ecosystem`` → CVE ``versions[].versionType`` for
# ECOSYSTEM-typed ranges. SEMVER/GIT ranges map directly below.
_ECOSYSTEM_VERSION_TYPE: dict[str, str] = {
    "Maven": "maven",
    "npm": "semver",
    "PyPI": "python",
    "Go": "semver",
    "NuGet": "semver",
    "RubyGems": "semver",
    "crates.io": "semver",
    "Packagist": "semver",
    "Pub": "semver",
    "Hex": "semver",
}

# OSV credit type → CVE credit ``type`` enum (lowercase, spaced).
_CREDIT_TYPE: dict[str, str] = {
    "FINDER": "finder",
    "REPORTER": "reporter",
    "ANALYST": "analyst",
    "COORDINATOR": "coordinator",
    "REMEDIATION_DEVELOPER": "remediation developer",
    "REMEDIATION_REVIEWER": "remediation reviewer",
    "REMEDIATION_VERIFIER": "remediation verifier",
    "TOOL": "tool",
    "SPONSOR": "sponsor",
    "OTHER": "other",
}


class CveValidationError(Exception):
    """Raised when a CVE record fails schema validation."""


class CveBuildError(Exception):
    """Raised when the advisory lacks data a valid CVE record requires.

    Distinct from :class:`CveValidationError` so the publication task can
    surface a clear, operator-actionable message ("add at least one
    reference") rather than a raw JSON-schema error.
    """


class CveAssignerNotConfigured(CveBuildError):
    """Raised when ``PUB_CVE_ASSIGNER_ORG_ID`` is unset/invalid at build time."""


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    schema = json.loads(_SCHEMA_PATH.read_text())
    resources = []
    for uri, filename, dialect in _CVSS_IMPORTS:
        contents = json.loads((_CVSS_DIR / filename).read_text())
        resources.append((uri, Resource.from_contents(contents, default_specification=dialect)))
    registry = Registry().with_resources(resources)
    return Draft7Validator(schema, registry=registry)


def _format_ts(dt) -> str:
    """RFC3339 UTC timestamp with millisecond precision and a ``Z`` suffix."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"


def build_cve(
    version: AdvisoryVersion,
    *,
    assigner_org_id: str,
    assigner_short_name: str = "",
    date_published=None,
    date_updated=None,
    date_reserved=None,
) -> dict[str, Any]:
    """Build a CVE 5.2.0 ``PUBLISHED`` record from a pinned advisory version.

    ``date_published``/``date_updated`` default to the version's
    ``created_at``. The publication task does not override them, so the
    output is deterministic — the same pinned version always produces
    byte-identical JSON (matching the OSV/CSAF builders).

    Raises :class:`CveAssignerNotConfigured` when ``assigner_org_id`` is
    empty or not a valid v4 UUID, and :class:`CveBuildError` when the
    advisory has no (well-formed) assigned CVE or lacks the affected/
    reference data a valid record requires.
    """
    payload = version.payload
    advisory = version.advisory

    cve_id = (payload.get("assigned_cve_id") or "").strip()
    if not cve_id:
        raise CveBuildError("Advisory has no assigned CVE; nothing to export.")
    # Defend against ids pinned into a frozen payload before the stricter
    # validator landed: the schema's cveId requires a 4–19 digit sequence.
    if not CVE_ID_RE.match(cve_id):
        raise CveBuildError(
            f"assigned CVE id {cve_id!r} is malformed; expected CVE-YYYY-NNNN "
            "with a 4–19 digit sequence number."
        )

    assigner_org_id = (assigner_org_id or "").strip()
    if not assigner_org_id:
        raise CveAssignerNotConfigured(
            "PUB_CVE_ASSIGNER_ORG_ID is not configured; cannot build a CVE record. "
            "Set it to the Eclipse Foundation CNA organization UUID."
        )
    if not _UUID_RE.match(assigner_org_id):
        raise CveAssignerNotConfigured(
            f"PUB_CVE_ASSIGNER_ORG_ID ({assigner_org_id!r}) is not a valid v4 UUID; "
            "set it to the Eclipse Foundation CNA organization UUID."
        )

    published = _format_ts(date_published or version.created_at)
    updated = _format_ts(date_updated or version.created_at)

    provider_metadata: dict[str, Any] = {"orgId": assigner_org_id, "dateUpdated": updated}
    if assigner_short_name:
        provider_metadata["shortName"] = assigner_short_name

    affected = _affected(payload, advisory)
    if not affected:
        raise CveBuildError(
            f"{cve_id}: a CVE record requires at least one affected product; "
            "add an affected package to the advisory before publishing."
        )
    references = _references(payload)
    if not references:
        raise CveBuildError(
            f"{cve_id}: a CVE record requires at least one reference; "
            "add a reference URL to the advisory before publishing."
        )

    cna: dict[str, Any] = {
        "providerMetadata": provider_metadata,
        "title": (payload.get("summary") or payload["advisory_id"])[:256],
        "descriptions": _descriptions(payload),
        "affected": affected,
        "references": references,
    }
    problem_types = _problem_types(payload)
    if problem_types:
        cna["problemTypes"] = problem_types
    metrics = _metrics(payload)
    if metrics:
        cna["metrics"] = metrics
    credits_block = _credits(payload)
    if credits_block:
        cna["credits"] = credits_block

    cve_metadata: dict[str, Any] = {
        "cveId": cve_id,
        "assignerOrgId": assigner_org_id,
        "state": "PUBLISHED",
        "datePublished": published,
        "dateUpdated": updated,
    }
    if assigner_short_name:
        cve_metadata["assignerShortName"] = assigner_short_name
    if date_reserved is not None:
        cve_metadata["dateReserved"] = _format_ts(date_reserved)

    return {
        "dataType": CVE_DATA_TYPE,
        "dataVersion": CVE_DATA_VERSION,
        "cveMetadata": cve_metadata,
        "containers": {"cna": cna},
    }


# ---------------------------------------------------------------------------
# Field builders
# ---------------------------------------------------------------------------


def _descriptions(payload: dict[str, Any]) -> list[dict[str, str]]:
    text = (payload.get("details") or "").strip() or (payload.get("summary") or "").strip()
    if not text:
        text = f"Security advisory {payload['advisory_id']}."
    # CVE description values are capped at 4096 characters.
    return [{"lang": "en", "value": text[:4096]}]


def _references(payload: dict[str, Any]) -> list[dict[str, str]]:
    """OSV references → CVE references, deduplicated by URL (uniqueItems).

    CVE reference ``tags`` are intentionally omitted: the upstream tag
    vocabulary lives in an external ``file:tags/…`` schema we do not vendor,
    and a bare ``{url}`` is the safest faithful representation.
    """
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for ref in payload.get("references") or []:
        url = (ref or {}).get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        out.append({"url": url})
    return out


def _affected(payload: dict[str, Any], advisory) -> list[dict[str, Any]]:
    # Vendor is read from the pinned payload (INV-VERSION-3); the live Project
    # row is only a fallback for versions pinned before ``project_name`` existed.
    vendor = (
        payload.get("project_name") or getattr(advisory.project, "name", "") or "Eclipse Foundation"
    ).strip()
    out: list[dict[str, Any]] = []
    for entry in payload.get("affected") or []:
        package = (entry or {}).get("package") or {}
        name = (package.get("name") or "").strip()
        if not name:
            continue
        ecosystem = (package.get("ecosystem") or "").strip()

        product: dict[str, Any] = {"vendor": vendor[:512], "product": name[:2048]}
        collection_url = _ECOSYSTEM_COLLECTION_URL.get(ecosystem)
        if collection_url:
            product["collectionURL"] = collection_url
            product["packageName"] = name[:2048]

        versions = _versions(entry, ecosystem)
        if versions:
            product["versions"] = versions
            # Only assert "everything not listed is unaffected" when every
            # emitted *range* uses an orderable versionType — otherwise a
            # consumer cannot place a real version inside the range and would
            # wrongly fall through to the default, mislabelling it safe.
            ranges = [v for v in versions if "lessThan" in v or "lessThanOrEqual" in v]
            if all(v.get("versionType") in _ORDERABLE_VERSION_TYPES for v in ranges):
                product["defaultStatus"] = "unaffected"
        else:
            # No version information could be derived: flag the whole product
            # affected rather than silently asserting it is safe.
            product["defaultStatus"] = "affected"
        out.append(product)
    return out


def _versions(entry: dict[str, Any], ecosystem: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rng in entry.get("ranges") or []:
        version_type = _version_type(rng.get("type", ""), ecosystem)
        out.extend(_versions_for_range(rng, version_type))
    # OSV may also carry an explicit enumerated affected version list.
    for v in entry.get("versions") or []:
        if isinstance(v, str) and v.strip():
            out.append({"version": v.strip()[:1024], "status": "affected"})
    # ``versions`` requires uniqueItems; drop exact duplicates while keeping order.
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in out:
        key = json.dumps(item, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _version_type(range_type: str, ecosystem: str) -> str:
    range_type = (range_type or "").upper()
    if range_type == "SEMVER":
        return "semver"
    if range_type == "GIT":
        return "git"
    # ECOSYSTEM (or anything else) → an ecosystem-derived hint, else "custom".
    return _ECOSYSTEM_VERSION_TYPE.get(ecosystem, "custom")


def _versions_for_range(rng: dict[str, Any], version_type: str) -> list[dict[str, Any]]:
    """Translate an OSV range's ordered events into CVE version entries.

    OSV ranges are an ordered event stream (``introduced`` opens a window;
    ``fixed`` / ``last_affected`` closes it). Each closed window becomes an
    ``affected`` range entry; an ``introduced`` left open at the end becomes
    an open-ended affected range (``lessThan: "*"``).

    OSV ``limit`` events are deliberately ignored: in OSV they bound the
    commit-graph traversal of a GIT range, they do **not** assert a fix, so
    mapping one to ``lessThan`` would falsely tell consumers that versions
    above the limit are fixed/unaffected.
    """
    out: list[dict[str, Any]] = []
    introduced: str | None = None
    for event in rng.get("events") or []:
        if not isinstance(event, dict) or len(event) != 1:
            continue
        ((kind, raw),) = event.items()
        value = (raw or "").strip() if isinstance(raw, str) else ""
        if not value:
            continue
        if kind == "introduced":
            introduced = value
        elif kind == "fixed":
            start = introduced if introduced is not None else "0"
            out.append(
                {
                    "version": start[:1024],
                    "status": "affected",
                    "versionType": version_type,
                    "lessThan": value[:1024],
                }
            )
            introduced = None
        elif kind == "last_affected":
            start = introduced if introduced is not None else "0"
            out.append(
                {
                    "version": start[:1024],
                    "status": "affected",
                    "versionType": version_type,
                    "lessThanOrEqual": value[:1024],
                }
            )
            introduced = None
    if introduced is not None:
        # Open-ended: affected from ``introduced`` upward with no known fix.
        # The schema's version syntax permits a trailing-asterisk upper bound.
        out.append(
            {
                "version": introduced[:1024],
                "status": "affected",
                "versionType": version_type,
                "lessThan": "*",
            }
        )
    return out


def _problem_types(payload: dict[str, Any]) -> list[dict[str, Any]]:
    descriptions: list[dict[str, str]] = []
    seen: set[str] = set()
    for cwe in payload.get("cwe_ids") or []:
        if not isinstance(cwe, str):
            continue
        cwe = cwe.strip().upper()
        if not cwe or cwe in seen:
            continue
        seen.add(cwe)
        descriptions.append(
            {
                "lang": "en",
                "description": (cwes.name_for(cwe) or cwe)[:4096],
                "cweId": cwe,
                "type": "CWE",
            }
        )
    if not descriptions:
        return []
    return [{"descriptions": descriptions}]


def _credits(payload: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for credit in payload.get("credits") or []:
        name = ((credit or {}).get("name") or "").strip()
        if not name:
            continue
        entry: dict[str, Any] = {"lang": "en", "value": name[:4096]}
        mapped = _CREDIT_TYPE.get(((credit or {}).get("type") or "").upper())
        if mapped:
            entry["type"] = mapped
        key = (entry["value"], entry.get("type"))
        if key in seen:
            continue
        seen.add(key)
        out.append(entry)
    return out


def _metrics(payload: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for sev in payload.get("severity") or []:
        metric = _cvss_metric(sev or {})
        if metric is None:
            continue
        # The metrics array is uniqueItems; duplicate severity entries (the
        # model permits them) must not produce duplicate metrics.
        key = json.dumps(metric, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(metric)
    return out


def _cvss_metric(sev: dict[str, Any]) -> dict[str, Any] | None:
    """Map one OSV severity entry to a CVE metric.

    Typed ``cvssVx_y`` when the vector parses (base score + severity computed
    via the ``cvss`` library); an ``other`` metric carrying the raw vector
    otherwise, so the severity survives even when it cannot be scored.
    """
    stype = sev.get("type")
    vector = (sev.get("score") or "").strip()
    if not vector:
        return None
    try:
        if stype == "CVSS_V2":
            c2 = CVSS2(vector)
            return {
                "cvssV2_0": {
                    "version": "2.0",
                    "vectorString": c2.clean_vector(),
                    "baseScore": float(c2.base_score),
                }
            }
        if stype == "CVSS_V3":
            c3 = CVSS3(vector)
            minor = c3.as_json().get("version", "3.1")
            field = "cvssV3_0" if minor == "3.0" else "cvssV3_1"
            return {
                field: {
                    "version": minor,
                    "vectorString": c3.clean_vector(),
                    "baseScore": float(c3.base_score),
                    "baseSeverity": c3.severities()[0].upper(),
                }
            }
        if stype == "CVSS_V4":
            c4 = CVSS4(vector)
            return {
                "cvssV4_0": {
                    "version": "4.0",
                    "vectorString": c4.clean_vector(),
                    "baseScore": float(c4.base_score),
                    "baseSeverity": c4.severity.upper(),
                }
            }
        if stype == "Ubuntu":
            return {"other": {"type": "Ubuntu", "content": {"severity": vector}}}
    except Exception:
        # Unparseable / malformed vector: carry it verbatim rather than drop it.
        return {"other": {"type": str(stype or "severity"), "content": {"vectorString": vector}}}
    return None


# ---------------------------------------------------------------------------
# Validation / serialization
# ---------------------------------------------------------------------------


def validate_cve(document: dict[str, Any]) -> None:
    validator = _validator()
    errors = list(validator.iter_errors(document))
    if not errors:
        return
    # The top-level schema is a oneOf (PUBLISHED/REJECTED), so a raw failure
    # surfaces at the document root with ``e.message`` set to the *entire*
    # instance repr — which would then be persisted into task.last_error and
    # audit metadata. ``best_match`` descends into the failing branch to the
    # most relevant sub-error, giving a compact, field-pointed message.
    best = best_match(errors)
    path = best.json_path if best is not None else "$"
    message = (best.message if best is not None else errors[0].message)[:500]
    raise CveValidationError(f"{path}: {message}")


def serialize_cve(document: dict[str, Any]) -> str:
    """Serialize a CVE dict to a deterministic JSON string for committing."""
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
