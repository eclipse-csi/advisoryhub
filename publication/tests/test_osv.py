from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from advisories.models import Advisory
from publication import osv as osv_mod


@pytest.fixture
def version(make_project, db):
    project = make_project("p")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-cccc-ffff-gggg",
        summary="Example XSS",
        details="Trust me, it's bad.",
        aliases=["CVE-2026-1234", "GHSA-xxxx-yyyy-zzzz"],
        cwe_ids=["CWE-79"],
        references=[{"type": "ADVISORY", "url": "https://example.org/a"}],
        affected=[
            {
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.5"}],
                    }
                ],
            }
        ],
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
        credits=[{"name": "Reporter Name", "type": "REPORTER"}],
    )
    return advisory.versions.get(version=1)


@pytest.mark.django_db
def test_build_osv_round_trip(version):
    fixed_dt = datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC)
    doc = osv_mod.build_osv(version, modified_at=fixed_dt, published_at=fixed_dt)
    assert doc["id"] == "ECL-cccc-ffff-gggg"
    assert doc["schema_version"] == "1.6.0"
    # OSV requires Z-suffixed UTC timestamps, not Python's `+00:00`.
    assert doc["modified"] == "2026-05-07T12:00:00.000Z"
    assert doc["published"] == "2026-05-07T12:00:00.000Z"
    assert doc["aliases"] == ["CVE-2026-1234", "GHSA-xxxx-yyyy-zzzz"]
    assert doc["summary"] == "Example XSS"
    assert doc["database_specific"]["cwe_ids"] == ["CWE-79"]
    osv_mod.validate_osv(doc)


@pytest.mark.django_db
def test_build_osv_passes_upstream_schema(version):
    """A realistic version payload must validate against the upstream OSV schema."""
    doc = osv_mod.build_osv(version)
    osv_mod.validate_osv(doc)


@pytest.mark.django_db
def test_build_osv_is_deterministic(version):
    fixed_dt = datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC)
    a = osv_mod.serialize_osv(
        osv_mod.build_osv(version, modified_at=fixed_dt, published_at=fixed_dt)
    )
    b = osv_mod.serialize_osv(
        osv_mod.build_osv(version, modified_at=fixed_dt, published_at=fixed_dt)
    )
    assert a == b


@pytest.mark.django_db
def test_validate_osv_rejects_missing_id(version):
    doc = osv_mod.build_osv(version)
    del doc["id"]
    with pytest.raises(osv_mod.OsvValidationError):
        osv_mod.validate_osv(doc)


@pytest.mark.django_db
def test_validate_osv_rejects_bad_id(version):
    doc = osv_mod.build_osv(version)
    doc["id"] = "lowercase-not-allowed"
    with pytest.raises(osv_mod.OsvValidationError):
        osv_mod.validate_osv(doc)


@pytest.mark.django_db
def test_serialize_osv_is_sorted_and_pretty(version):
    doc = osv_mod.build_osv(version)
    out = osv_mod.serialize_osv(doc)
    parsed = json.loads(out)
    assert parsed == doc
    # First top-level key after re-parse should be alphabetically first
    keys = list(parsed.keys())
    assert keys == sorted(keys)


@pytest.mark.django_db
def test_build_osv_merges_assigned_cve_into_aliases(make_project):
    """assigned_cve_id is a first-class advisory field; it must surface in the
    OSV alias list at serialization time even though the editor never put it
    in advisory.aliases."""
    project = make_project("p2")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-hhhh-jjjj-mmmm",
        summary="A bug",
        aliases=["GHSA-xxxx-yyyy-zzzz"],
        assigned_cve_id="CVE-2026-0001",
    )
    v = advisory.versions.get(version=1)
    doc = osv_mod.build_osv(v)
    assert doc["aliases"] == ["CVE-2026-0001", "GHSA-xxxx-yyyy-zzzz"]
    osv_mod.validate_osv(doc)


@pytest.mark.django_db
def test_build_osv_deduplicates_assigned_cve_when_also_in_aliases(make_project):
    project = make_project("p3")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-2222-3333-4444",
        summary="A bug",
        aliases=["CVE-2026-0001"],
        assigned_cve_id="CVE-2026-0001",
    )
    v = advisory.versions.get(version=1)
    doc = osv_mod.build_osv(v)
    assert doc["aliases"] == ["CVE-2026-0001"]


def test_python_ecosystem_set_matches_vendored_schema():
    """Guard against drift between ``advisories.ecosystems.OSV_ECOSYSTEMS`` and the
    vendored schema's ``ecosystemWithSuffix`` pattern.

    Compares against ``ecosystemWithSuffix`` (which includes ``GIT``), NOT
    ``ecosystemName`` (which omits it). If a schema sync changes the pattern,
    update ``OSV_ECOSYSTEMS`` to match (or vice versa).
    """
    import re

    from advisories.ecosystems import OSV_ECOSYSTEMS

    schema = json.loads(osv_mod._SCHEMA_PATH.read_text())
    pattern = schema["$defs"]["ecosystemWithSuffix"]["pattern"]
    # pattern is ^(<alt>|<alt>|...)(:.+)?$ — pull the alternation group out and
    # un-escape names like ``crates\.io``.
    m = re.fullmatch(r"\^\((.*)\)\(:\.\+\)\?\$", pattern)
    assert m, f"unexpected ecosystemWithSuffix shape: {pattern}"
    schema_names = [re.sub(r"\\(.)", r"\1", alt) for alt in m.group(1).split("|")]
    assert list(OSV_ECOSYSTEMS) == schema_names
