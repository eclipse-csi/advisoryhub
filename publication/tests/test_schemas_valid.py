"""Each vendored JSON schema is itself a valid JSON Schema.

The publication build tests (``test_osv`` / ``test_csaf`` / ``test_cve``) already
validate real payloads against these schemas — that catches a refreshed schema
that *rejects* good data. This module complements them by catching a schema that
is itself malformed or invalid for its declared dialect (a refresh that corrupts
the file, or introduces a keyword the dialect forbids), which a happy-path
payload might not surface. Together they are the gate that lets a schema *refresh*
be auto-merged on green CI (see the vendored-asset updater).

No DB — pure file checks.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema.validators import validator_for

_SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"

_CVSS_FILES = sorted(_SCHEMAS_DIR.glob("cvss/*.json"))
_SCHEMA_FILES = [
    _SCHEMAS_DIR / "osv.upstream.json",
    _SCHEMAS_DIR / "csaf.upstream.json",
    _SCHEMAS_DIR / "cve.upstream.json",
    *_CVSS_FILES,
]


def test_expected_schema_files_present():
    """A moved/renamed schema would otherwise make the parametrized test below
    silently cover fewer files."""
    names = {p.name for p in _SCHEMA_FILES}
    assert {"osv.upstream.json", "csaf.upstream.json", "cve.upstream.json"} <= names
    # OSV CVE record references its four CVSS sub-schemas (v2.0/v3.0/v3.1/v4.0).
    assert len(_CVSS_FILES) == 4, f"expected 4 cvss/*.json, found {len(_CVSS_FILES)}"


@pytest.mark.parametrize("schema_path", _SCHEMA_FILES, ids=lambda p: p.name)
def test_vendored_schema_is_valid_json_schema(schema_path: Path):
    """Loads the schema and validates it against its own declared dialect's
    metaschema (``$schema``). Raises ``SchemaError`` if the file is not a valid
    JSON Schema."""
    schema = json.loads(schema_path.read_text())
    validator_cls = validator_for(schema)
    validator_cls.check_schema(schema)


def test_osv_schema_keeps_ecl_prefix_patch():
    """The local ``ECL-`` prefix patch (``$defs/prefix.pattern``) must survive a
    schema refresh — the re-vendor script re-applies it after pulling upstream.
    This fails loudly if a refresh ever drops it, so an OSV bump that strips the
    Eclipse advisory-id prefix cannot be auto-merged."""
    osv = json.loads((_SCHEMAS_DIR / "osv.upstream.json").read_text())
    pattern = osv["$defs"]["prefix"]["pattern"]
    assert "ECL" in pattern, "OSV ECL- prefix patch missing — re-apply after refresh"
