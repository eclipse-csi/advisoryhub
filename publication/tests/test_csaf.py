from __future__ import annotations

from datetime import UTC, datetime

import pytest

from advisories.models import Advisory
from publication import csaf as csaf_mod


@pytest.fixture
def version(make_project, db):
    project = make_project("p")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-cccc-ffff-gggg",
        summary="Example issue",
        details="Long description.",
        aliases=["CVE-2026-1234", "GHSA-aaaa-bbbb-cccc"],
        cwe_ids=["CWE-79"],
        references=[
            {"type": "ADVISORY", "url": "https://example.org/a"},
            {"type": "FIX", "url": "https://example.org/fix"},
        ],
    )
    return advisory.versions.get(version=1)


@pytest.mark.django_db
def test_build_csaf_has_required_top_level(version):
    fixed_dt = datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC)
    doc = csaf_mod.build_csaf(
        version,
        current_release_date=fixed_dt,
        initial_release_date=fixed_dt,
    )
    assert doc["document"]["csaf_version"] == "2.0"
    assert doc["document"]["category"] == "csaf_security_advisory"
    assert doc["document"]["tracking"]["id"] == "ECL-cccc-ffff-gggg"
    assert doc["document"]["tracking"]["status"] == "final"
    assert len(doc["vulnerabilities"]) == 1
    vuln = doc["vulnerabilities"][0]
    assert vuln["cve"] == "CVE-2026-1234"
    assert vuln["cwe"] == {"id": "CWE-79", "name": "CWE-79"}
    csaf_mod.validate_csaf(doc)


@pytest.mark.django_db
def test_validate_csaf_rejects_missing_publisher(version):
    doc = csaf_mod.build_csaf(version)
    del doc["document"]["publisher"]
    with pytest.raises(csaf_mod.CsafValidationError):
        csaf_mod.validate_csaf(doc)


@pytest.mark.django_db
def test_validate_csaf_rejects_wrong_csaf_version(version):
    doc = csaf_mod.build_csaf(version)
    doc["document"]["csaf_version"] = "1.2"
    with pytest.raises(csaf_mod.CsafValidationError):
        csaf_mod.validate_csaf(doc)


@pytest.mark.django_db
def test_serialize_csaf_is_deterministic(version):
    fixed_dt = datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC)
    a = csaf_mod.serialize_csaf(
        csaf_mod.build_csaf(version, current_release_date=fixed_dt, initial_release_date=fixed_dt)
    )
    b = csaf_mod.serialize_csaf(
        csaf_mod.build_csaf(version, current_release_date=fixed_dt, initial_release_date=fixed_dt)
    )
    assert a == b


@pytest.mark.django_db
def test_build_csaf_assigned_cve_lands_in_vuln_cve(make_project):
    """The EF-assigned CVE must populate vuln.cve in CSAF, with editor-managed
    aliases falling through to vuln.ids."""
    project = make_project("p2")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-9999-cccc-ffff",
        summary="Issue with assigned CVE",
        aliases=["GHSA-aaaa-bbbb-cccc"],
        assigned_cve_id="CVE-2026-0001",
    )
    v = advisory.versions.get(version=1)
    doc = csaf_mod.build_csaf(v)
    vuln = doc["vulnerabilities"][0]
    assert vuln["cve"] == "CVE-2026-0001"
    ids_text = {entry["text"] for entry in vuln.get("ids", [])}
    assert "GHSA-aaaa-bbbb-cccc" in ids_text
    assert "CVE-2026-0001" not in ids_text
    csaf_mod.validate_csaf(doc)


@pytest.mark.django_db
def test_build_csaf_assigned_cve_wins_over_aliases_cve(make_project):
    """If the editor also added a different CVE to aliases, vuln.cve still
    reflects the EF-assigned one (biased to the front of the merge list)."""
    project = make_project("p3")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-8888-7777-6666",
        summary="Conflicting CVEs",
        aliases=["CVE-2026-9999"],
        assigned_cve_id="CVE-2026-0001",
    )
    v = advisory.versions.get(version=1)
    doc = csaf_mod.build_csaf(v)
    vuln = doc["vulnerabilities"][0]
    assert vuln["cve"] == "CVE-2026-0001"
