from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from advisories.models import Advisory
from publication import cve as cve_mod

# A schema-valid v4 UUID standing in for the Eclipse Foundation CNA org id.
TEST_ORG_ID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"


def _build(version, **kwargs):
    kwargs.setdefault("assigner_org_id", TEST_ORG_ID)
    kwargs.setdefault("assigner_short_name", "eclipse")
    return cve_mod.build_cve(version, **kwargs)


@pytest.fixture
def version(make_project, db):
    project = make_project("acme")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-cccc-ffff-gggg",
        summary="Example XSS",
        details="Reflected XSS in the example handler.",
        aliases=["GHSA-xxxx-yyyy-zzzz"],
        assigned_cve_id="CVE-2026-0001",
        cwe_ids=["CWE-79"],
        references=[
            {"type": "ADVISORY", "url": "https://example.org/a"},
            {"type": "FIX", "url": "https://example.org/fix"},
        ],
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


# ---- Happy path ----------------------------------------------------------


@pytest.mark.django_db
def test_build_cve_round_trip(version):
    fixed_dt = datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC)
    doc = _build(version, date_published=fixed_dt, date_updated=fixed_dt)

    assert doc["dataType"] == "CVE_RECORD"
    assert doc["dataVersion"] == "5.2.0"
    meta = doc["cveMetadata"]
    assert meta["cveId"] == "CVE-2026-0001"
    assert meta["state"] == "PUBLISHED"
    assert meta["assignerOrgId"] == TEST_ORG_ID
    assert meta["assignerShortName"] == "eclipse"
    assert meta["datePublished"] == "2026-05-07T12:00:00.000Z"

    cna = doc["containers"]["cna"]
    assert cna["providerMetadata"]["orgId"] == TEST_ORG_ID
    assert cna["descriptions"][0]["lang"] == "en"
    assert cna["descriptions"][0]["value"] == "Reflected XSS in the example handler."
    assert cna["problemTypes"][0]["descriptions"][0]["cweId"] == "CWE-79"
    # CWE title is looked up from the vendored catalog, not just the id.
    assert "Cross-site Scripting" in cna["problemTypes"][0]["descriptions"][0]["description"]

    cve_mod.validate_cve(doc)


@pytest.mark.django_db
def test_build_cve_passes_upstream_schema(version):
    """A realistic payload must validate against the vendored CVE 5.2.0 schema."""
    cve_mod.validate_cve(_build(version))


@pytest.mark.django_db
def test_build_cve_is_deterministic(version):
    fixed_dt = datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC)
    a = cve_mod.serialize_cve(_build(version, date_published=fixed_dt, date_updated=fixed_dt))
    b = cve_mod.serialize_cve(_build(version, date_published=fixed_dt, date_updated=fixed_dt))
    assert a == b


@pytest.mark.django_db
def test_serialize_cve_is_sorted_and_pretty(version):
    out = cve_mod.serialize_cve(_build(version))
    parsed = json.loads(out)
    keys = list(parsed.keys())
    assert keys == sorted(keys)


# ---- Affected mapping ----------------------------------------------------


@pytest.mark.django_db
def test_build_cve_affected_maps_package_and_ranges(version):
    affected = _build(version)["containers"]["cna"]["affected"]
    assert len(affected) == 1
    entry = affected[0]
    # vendor falls back to the (title-cased) project name; Maven ⇒ package coords.
    assert entry["vendor"] == "Acme"
    assert entry["product"] == "org.example:lib"
    assert entry["collectionURL"] == "https://repo.maven.apache.org/maven2"
    assert entry["packageName"] == "org.example:lib"
    assert entry["defaultStatus"] == "unaffected"
    assert entry["versions"] == [
        {
            "version": "1.0.0",
            "status": "affected",
            "versionType": "maven",
            "lessThan": "1.0.5",
        }
    ]


@pytest.mark.django_db
def test_build_cve_open_ended_range_uses_wildcard_upper_bound(make_project):
    project = make_project("p-open")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-2222-3333-4444",
        summary="No fix yet",
        assigned_cve_id="CVE-2026-0002",
        references=[{"type": "WEB", "url": "https://example.org/x"}],
        affected=[
            {
                "package": {"ecosystem": "PyPI", "name": "examplepkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
    )
    version = advisory.versions.get(version=1)
    doc = _build(version)
    versions = doc["containers"]["cna"]["affected"][0]["versions"]
    assert versions == [
        {"version": "0", "status": "affected", "versionType": "python", "lessThan": "*"}
    ]
    cve_mod.validate_cve(doc)


@pytest.mark.django_db
def test_build_cve_last_affected_maps_to_less_than_or_equal(make_project):
    project = make_project("p-la")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-5555-6666-7777",
        summary="last_affected range",
        assigned_cve_id="CVE-2026-0003",
        references=[{"type": "WEB", "url": "https://example.org/x"}],
        affected=[
            {
                "package": {"ecosystem": "npm", "name": "examplepkg"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "1.0.0"}, {"last_affected": "1.2.3"}],
                    }
                ],
            }
        ],
    )
    version = advisory.versions.get(version=1)
    versions = _build(version)["containers"]["cna"]["affected"][0]["versions"]
    assert versions == [
        {
            "version": "1.0.0",
            "status": "affected",
            "versionType": "semver",
            "lessThanOrEqual": "1.2.3",
        }
    ]


# ---- Metrics -------------------------------------------------------------


@pytest.mark.django_db
def test_build_cve_metrics_typed_cvss_v3_1(version):
    metrics = _build(version)["containers"]["cna"]["metrics"]
    assert metrics == [
        {
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "baseScore": 6.1,
                "baseSeverity": "MEDIUM",
            }
        }
    ]


@pytest.mark.django_db
def test_build_cve_metrics_cvss_v4(make_project):
    project = make_project("p-v4")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-8888-9999-aaaa",
        summary="v4 severity",
        assigned_cve_id="CVE-2026-0004",
        references=[{"type": "WEB", "url": "https://example.org/x"}],
        affected=[
            {
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}
                ],
            }
        ],
        severity=[
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            }
        ],
    )
    version = advisory.versions.get(version=1)
    doc = _build(version)
    metric = doc["containers"]["cna"]["metrics"][0]["cvssV4_0"]
    assert metric["version"] == "4.0"
    assert metric["baseSeverity"] == "CRITICAL"
    assert isinstance(metric["baseScore"], float)
    cve_mod.validate_cve(doc)


@pytest.mark.django_db
def test_build_cve_unparseable_vector_falls_back_to_other(make_project):
    project = make_project("p-bad")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-bbbb-cccc-dddd",
        summary="garbled vector",
        assigned_cve_id="CVE-2026-0005",
        references=[{"type": "WEB", "url": "https://example.org/x"}],
        affected=[
            {
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}
                ],
            }
        ],
        # Passes the model's loose severity validator but is not a real CVSS3 vector.
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/NONSENSE"}],
    )
    version = advisory.versions.get(version=1)
    doc = _build(version)
    metric = doc["containers"]["cna"]["metrics"][0]
    assert "other" in metric
    assert metric["other"]["content"]["vectorString"] == "CVSS:3.1/NONSENSE"
    cve_mod.validate_cve(doc)


# ---- Credits -------------------------------------------------------------


@pytest.mark.django_db
def test_build_cve_credits_mapped(version):
    credits_block = _build(version)["containers"]["cna"]["credits"]
    assert credits_block == [{"lang": "en", "value": "Reporter Name", "type": "reporter"}]


# ---- Required-data guards ------------------------------------------------


@pytest.mark.django_db
def test_build_cve_requires_assigned_cve(make_project):
    project = make_project("p-noid")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-eeee-ffff-gggg",
        summary="no cve",
        references=[{"type": "WEB", "url": "https://example.org/x"}],
    )
    version = advisory.versions.get(version=1)
    with pytest.raises(cve_mod.CveBuildError):
        _build(version)


@pytest.mark.django_db
def test_build_cve_requires_assigner_org_id(version):
    with pytest.raises(cve_mod.CveAssignerNotConfigured):
        cve_mod.build_cve(version, assigner_org_id="")


@pytest.mark.django_db
def test_build_cve_requires_affected(make_project):
    project = make_project("p-noaff")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-hhhh-jjjj-kkkk",
        summary="no affected",
        assigned_cve_id="CVE-2026-0006",
        references=[{"type": "WEB", "url": "https://example.org/x"}],
    )
    version = advisory.versions.get(version=1)
    with pytest.raises(cve_mod.CveBuildError):
        _build(version)


@pytest.mark.django_db
def test_build_cve_requires_references(make_project):
    project = make_project("p-noref")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-mmmm-nnnn-pppp",
        summary="no refs",
        assigned_cve_id="CVE-2026-0007",
        affected=[
            {
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}
                ],
            }
        ],
    )
    version = advisory.versions.get(version=1)
    with pytest.raises(cve_mod.CveBuildError):
        _build(version)


# ---- Validation ----------------------------------------------------------


@pytest.mark.django_db
def test_validate_cve_rejects_bad_assigner_uuid(version):
    doc = _build(version)
    doc["cveMetadata"]["assignerOrgId"] = "not-a-uuid"
    with pytest.raises(cve_mod.CveValidationError):
        cve_mod.validate_cve(doc)


# ---- Regression tests (adversarial-review findings) ----------------------


@pytest.mark.django_db
def test_build_cve_dedups_metrics(make_project):
    """Duplicate severity entries must not yield duplicate metrics (uniqueItems)."""
    project = make_project("p-dupmetric")
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-dup1-dup2-dup3",
        summary="dup severity",
        assigned_cve_id="CVE-2026-0010",
        references=[{"type": "WEB", "url": "https://example.org/x"}],
        affected=[
            {
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}
                ],
            }
        ],
        severity=[{"type": "CVSS_V3", "score": vec}, {"type": "CVSS_V3", "score": vec}],
    )
    version = advisory.versions.get(version=1)
    doc = _build(version)
    assert len(doc["containers"]["cna"]["metrics"]) == 1
    cve_mod.validate_cve(doc)


@pytest.mark.django_db
def test_build_cve_ignores_git_limit_event(make_project):
    """OSV `limit` bounds a GIT traversal; it must NOT become a `lessThan` fix."""
    project = make_project("p-gitlimit")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-git1-git2-git3",
        summary="git range with limit",
        assigned_cve_id="CVE-2026-0011",
        references=[{"type": "WEB", "url": "https://example.org/x"}],
        affected=[
            {
                "package": {"ecosystem": "GitHub", "name": "org/repo"},
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [{"introduced": "0"}, {"limit": "refs/heads/release-1.x"}],
                    }
                ],
            }
        ],
    )
    version = advisory.versions.get(version=1)
    entry = _build(version)["containers"]["cna"]["affected"][0]
    versions = entry["versions"]
    # introduced + limit-only ⇒ open-ended affected range, never lessThan=<limit>.
    assert versions == [
        {"version": "0", "status": "affected", "versionType": "git", "lessThan": "*"}
    ]
    assert all(v.get("lessThan") != "refs/heads/release-1.x" for v in versions)
    # git is not an orderable versionType ⇒ no blanket "unaffected" default.
    assert "defaultStatus" not in entry


@pytest.mark.django_db
def test_build_cve_non_orderable_versiontype_omits_default_status(make_project):
    """An unknown ecosystem maps to versionType 'custom'; defaultStatus must
    not assert 'unaffected' because the range cannot be ordered."""
    project = make_project("p-custom")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-cust-cust-cust",
        summary="custom ecosystem",
        assigned_cve_id="CVE-2026-0012",
        references=[{"type": "WEB", "url": "https://example.org/x"}],
        affected=[
            {
                "package": {"ecosystem": "SomethingExotic", "name": "exotic-pkg"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.5"}]}
                ],
            }
        ],
    )
    version = advisory.versions.get(version=1)
    entry = _build(version)["containers"]["cna"]["affected"][0]
    assert entry["versions"][0]["versionType"] == "custom"
    assert "defaultStatus" not in entry
    cve_mod.validate_cve(_build(version))


@pytest.mark.django_db
def test_build_cve_rejects_short_cve_id(make_project):
    """A short (sub-4-digit) id pinned into a frozen payload is rejected with a
    clear build error rather than an opaque schema failure."""
    project = make_project("p-shortid")
    # objects.create bypasses field validators, simulating a pre-tightening pin.
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-shrt-shrt-shrt",
        summary="short cve",
        assigned_cve_id="CVE-2026-123",
        references=[{"type": "WEB", "url": "https://example.org/x"}],
        affected=[
            {
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}
                ],
            }
        ],
    )
    version = advisory.versions.get(version=1)
    with pytest.raises(cve_mod.CveBuildError):
        _build(version)


@pytest.mark.django_db
def test_build_cve_rejects_malformed_assigner_uuid(version):
    with pytest.raises(cve_mod.CveAssignerNotConfigured):
        cve_mod.build_cve(version, assigner_org_id="not-a-uuid")


@pytest.mark.django_db
def test_build_cve_vendor_uses_pinned_project_name(version):
    """INV-VERSION-3: a project rename must not change an already-pinned version's
    exported vendor."""
    project = version.advisory.project
    project.name = "Renamed Project"
    project.save(update_fields=["name"])
    # The pinned v1 payload still carries the original name.
    vendor = _build(version)["containers"]["cna"]["affected"][0]["vendor"]
    assert vendor == "Acme"


@pytest.mark.django_db
def test_validate_cve_error_is_compact_and_field_pointed(version):
    """A validation failure must not dump the whole document into the error."""
    doc = _build(version)
    doc["cveMetadata"]["cveId"] = "not-a-cve-id"
    try:
        cve_mod.validate_cve(doc)
    except cve_mod.CveValidationError as exc:
        msg = str(exc)
    else:
        raise AssertionError("expected CveValidationError")
    # Compact, and does not embed the full record (e.g. the descriptions text).
    assert len(msg) < 600
    assert "Reflected XSS in the example handler." not in msg


@pytest.mark.django_db
def test_validate_cve_rejects_missing_descriptions(version):
    doc = _build(version)
    del doc["containers"]["cna"]["descriptions"]
    with pytest.raises(cve_mod.CveValidationError):
        cve_mod.validate_cve(doc)


# ---- Rejected record (withdrawal) ----------------------------------------


def _build_rejected(version, **kwargs):
    kwargs.setdefault("assigner_org_id", TEST_ORG_ID)
    kwargs.setdefault("assigner_short_name", "eclipse")
    kwargs.setdefault("reason", "Duplicate of CVE-2026-0001.")
    return cve_mod.build_rejected_cve(version, **kwargs)


@pytest.mark.django_db
def test_build_rejected_cve_round_trip(version):
    rejected_dt = datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)
    doc = _build_rejected(version, date_rejected=rejected_dt)

    assert doc["dataType"] == "CVE_RECORD"
    assert doc["dataVersion"] == "5.2.0"
    meta = doc["cveMetadata"]
    assert meta["cveId"] == "CVE-2026-0001"
    assert meta["state"] == "REJECTED"
    assert meta["assignerOrgId"] == TEST_ORG_ID
    assert meta["assignerShortName"] == "eclipse"
    assert meta["dateRejected"] == "2026-06-07T12:00:00.000Z"
    assert meta["dateUpdated"] == "2026-06-07T12:00:00.000Z"

    cna = doc["containers"]["cna"]
    assert cna["providerMetadata"]["orgId"] == TEST_ORG_ID
    assert cna["rejectedReasons"] == [{"lang": "en", "value": "Duplicate of CVE-2026-0001."}]
    # A rejected record carries none of the published-only content.
    assert "affected" not in cna
    assert "references" not in cna
    assert "descriptions" not in cna

    cve_mod.validate_cve(doc)


@pytest.mark.django_db
def test_build_rejected_cve_passes_upstream_schema(version):
    cve_mod.validate_cve(_build_rejected(version))


@pytest.mark.django_db
def test_build_rejected_cve_is_deterministic(version):
    rejected_dt = datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)
    a = cve_mod.serialize_cve(_build_rejected(version, date_rejected=rejected_dt))
    b = cve_mod.serialize_cve(_build_rejected(version, date_rejected=rejected_dt))
    assert a == b


@pytest.mark.django_db
def test_build_rejected_cve_carries_date_published_when_set(version):
    """The original publication date is retained alongside dateRejected
    (matching the cve.org rejected-record convention)."""
    advisory = version.advisory
    advisory.published_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    advisory.save(update_fields=["published_at"])
    doc = _build_rejected(version)
    assert doc["cveMetadata"]["datePublished"] == "2026-01-02T03:04:05.000Z"


@pytest.mark.django_db
def test_build_rejected_cve_omits_date_published_when_never_published(version):
    # The fixture advisory was never published, so published_at is None.
    assert version.advisory.published_at is None
    assert "datePublished" not in _build_rejected(version)["cveMetadata"]


@pytest.mark.django_db
def test_build_rejected_cve_requires_reason(version):
    with pytest.raises(cve_mod.CveBuildError):
        _build_rejected(version, reason="   ")


@pytest.mark.django_db
def test_build_rejected_cve_requires_assigned_cve(make_project):
    project = make_project("p-rej-noid")
    advisory = Advisory.objects.create(
        project=project,
        advisory_id="ECL-rej1-rej2-rej3",
        summary="no cve to reject",
    )
    version = advisory.versions.get(version=1)
    with pytest.raises(cve_mod.CveBuildError):
        _build_rejected(version)


@pytest.mark.django_db
def test_build_rejected_cve_requires_assigner_org_id(version):
    with pytest.raises(cve_mod.CveAssignerNotConfigured):
        cve_mod.build_rejected_cve(version, assigner_org_id="", reason="dup")
