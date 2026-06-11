"""Prompts and JSON schemas for the two similarity LLM calls.

Inputs are always built from the pinned ``SimilarityCheck.version`` payload
(INV-SIM-4) and truncated to keep token spend bounded. The JSON schemas stay
deliberately plain — structured-output modes do not support numeric bounds or
string-length constraints, so confidence clamping happens in service code.
"""

from __future__ import annotations

import json

FINGERPRINT_MAX_TOKENS = 1024
JUDGE_MAX_TOKENS = 4096

_FINGERPRINT_DETAILS_LIMIT = 6000
_JUDGE_DETAILS_LIMIT = 4000
_FALLBACK_SUMMARY_LIMIT = 300
_FALLBACK_DETAILS_LIMIT = 700
_SEVERITY_LIMIT = 500

FINGERPRINT_SYSTEM = (
    "You are a security-advisory analyst. You produce compact, normalized digests of "
    "vulnerability reports so they can be compared for duplicates. Use only the provided "
    "text; use empty strings or empty arrays for facts the text does not state. "
    "Reply with JSON only."
)

FINGERPRINT_SCHEMA = {
    "type": "object",
    "properties": {
        "vuln_class": {
            "type": "string",
            "description": "Vulnerability class, e.g. XSS, SQL injection, path traversal, DoS",
        },
        "component": {
            "type": "string",
            "description": "Affected component, package, or subsystem",
        },
        "attack_vector": {
            "type": "string",
            "description": "How the flaw is reached, e.g. crafted HTTP request, malicious archive",
        },
        "affected_versions": {
            "type": "string",
            "description": "Compact affected-version statement",
        },
        "identifiers": {"type": "array", "items": {"type": "string"}},
        "digest": {
            "type": "string",
            "description": "3-5 sentence normalized description of the flaw",
        },
    },
    "required": [
        "vuln_class",
        "component",
        "attack_vector",
        "affected_versions",
        "identifiers",
        "digest",
    ],
    "additionalProperties": False,
}

JUDGE_SYSTEM = (
    "You are a security-advisory triage assistant detecting duplicate reports. Given a NEW "
    "report and CANDIDATE advisories from the same project, score how likely each candidate "
    "describes the SAME vulnerability as the new report. 100 means certainly the same flaw; "
    "0 means unrelated. The same component with a clearly different flaw must score low "
    "(under 30). Shared identifiers (CVE/GHSA) imply very high confidence. Score every "
    "candidate, use only the integer ids given, and never invent ids. Each rationale is one "
    "short sentence. Reply with JSON only."
)

JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "matches": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "integer"},
                    "confidence": {"type": "integer", "description": "0-100"},
                    "rationale": {"type": "string", "description": "One short sentence"},
                },
                "required": ["candidate_id", "confidence", "rationale"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["matches"],
    "additionalProperties": False,
}


def payload_identifiers(payload: dict) -> list[str]:
    """CVE/GHSA/alias identifiers from a payload (or live-field subset)."""
    out: list[str] = []
    for alias in payload.get("aliases") or []:
        if isinstance(alias, str) and alias and alias not in out:
            out.append(alias)
    for key in ("assigned_cve_id", "ghsa_id"):
        value = payload.get(key)
        if isinstance(value, str) and value and value not in out:
            out.append(value)
    return out


def payload_package_names(payload: dict) -> list[str]:
    """OSV-style affected package names from a payload."""
    names: list[str] = []
    for entry in payload.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if isinstance(name, str) and name and name not in names:
            names.append(name)
    return names


def fingerprint_user(payload: dict) -> str:
    severity = json.dumps(payload.get("severity") or [], ensure_ascii=False)
    cwes = ", ".join(str(c) for c in (payload.get("cwe_ids") or []))
    return (
        "Create a duplicate-detection fingerprint for this vulnerability report.\n\n"
        f"Summary: {payload.get('summary') or ''}\n"
        f"Details (may be truncated): {(payload.get('details') or '')[:_FINGERPRINT_DETAILS_LIMIT]}\n"
        f"Identifiers (CVE/GHSA/aliases): {', '.join(payload_identifiers(payload))}\n"
        f"Affected packages: {', '.join(payload_package_names(payload))}\n"
        f"Severity: {severity[:_SEVERITY_LIMIT]}\n"
        f"CWEs: {cwes}\n\n"
        "Keep the digest under 120 words."
    )


def render_fingerprint(data: dict) -> str:
    """Canonical single-string fingerprint persisted and fed to the judge."""
    identifiers = ", ".join(str(i) for i in (data.get("identifiers") or []))
    return "; ".join(
        [
            f"class: {data.get('vuln_class') or ''}",
            f"component: {data.get('component') or ''}",
            f"vector: {data.get('attack_vector') or ''}",
            f"versions: {data.get('affected_versions') or ''}",
            f"ids: {identifiers}",
            f"digest: {data.get('digest') or ''}",
        ]
    )


def candidate_block(
    *,
    pk: int,
    advisory_id: str,
    state: str,
    fingerprint: str | None,
    summary: str,
    details: str,
    identifiers: list[str],
) -> str:
    """One candidate's judge-prompt block: fingerprint, or a raw excerpt fallback."""
    lines = [f"[id={pk}] {advisory_id} (state={state})"]
    if fingerprint:
        lines.append(f"  fingerprint: {fingerprint}")
    else:
        if summary:
            lines.append(f"  summary: {summary[:_FALLBACK_SUMMARY_LIMIT]}")
        if details:
            lines.append(f"  details: {details[:_FALLBACK_DETAILS_LIMIT]}")
        if identifiers:
            lines.append(f"  identifiers: {', '.join(identifiers)}")
    return "\n".join(lines)


def judge_user(*, advisory_id: str, payload: dict, fingerprint: str, candidates: str) -> str:
    return (
        f"NEW REPORT ({advisory_id}):\n"
        f"fingerprint: {fingerprint}\n"
        f"summary: {payload.get('summary') or ''}\n"
        f"details (may be truncated): {(payload.get('details') or '')[:_JUDGE_DETAILS_LIMIT]}\n"
        f"identifiers: {', '.join(payload_identifiers(payload))}\n"
        f"affected packages: {', '.join(payload_package_names(payload))}\n\n"
        f"CANDIDATES:\n{candidates}"
    )
