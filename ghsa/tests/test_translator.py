"""Translator unit tests — pure data, no DB."""

from __future__ import annotations

import pytest

from advisories.models import Advisory, GhsaState, Kind
from ghsa.translator import apply_ghsa_to_advisory


@pytest.mark.django_db
def test_translator_maps_summary_description_severity(make_project, ghsa_payload):
    project = make_project("p1")
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
    )
    result = apply_ghsa_to_advisory(advisory, ghsa_payload)
    assert advisory.summary == "Path traversal in example library"
    assert "path traversal" in advisory.details.lower()
    assert any(s["type"] == "CVSS_V3" for s in advisory.severity)
    assert advisory.cwe_ids == ["CWE-22"]
    assert result.ghsa_state == GhsaState.PUBLISHED
    assert result.cve_id_from_ghsa is None
    assert {"summary", "details", "severity", "cwe_ids"} <= set(result.changed_field_names)


@pytest.mark.django_db
def test_translator_extracts_cve_id_from_top_level(make_project, ghsa_payload):
    ghsa_payload = dict(ghsa_payload, cve_id="CVE-2026-9999")
    project = make_project("p2")
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
    )
    result = apply_ghsa_to_advisory(advisory, ghsa_payload)
    assert result.cve_id_from_ghsa == "CVE-2026-9999"
    # CVE id is NOT exposed as an alias — assigned_cve_id is the
    # authoritative slot for it.
    assert "CVE-2026-9999" not in advisory.aliases


@pytest.mark.django_db
def test_translator_translates_affected_versions(make_project, ghsa_payload):
    project = make_project("p3")
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
    )
    apply_ghsa_to_advisory(advisory, ghsa_payload)
    assert len(advisory.affected) == 1
    entry = advisory.affected[0]
    assert entry["package"]["name"] == "org.example:library"
    assert entry["package"]["ecosystem"] == "Maven"
    events = entry["ranges"][0]["events"]
    assert {"introduced": "1.0.0"} in events
    assert {"fixed": "1.2.3"} in events


@pytest.mark.django_db
def test_translator_translates_credits(make_project, ghsa_payload):
    project = make_project("p4")
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
    )
    apply_ghsa_to_advisory(advisory, ghsa_payload)
    assert advisory.credits == [{"name": "reporter1", "type": "REPORTER"}]


@pytest.mark.django_db
def test_translator_drops_unsafe_scheme_references(make_project, ghsa_payload):
    # A repo-advisory author (or PVR reporter) can set a reference URL; the
    # detail page renders it as a live <a href>, and this import path saves
    # without full_clean(), so the translator itself must drop dangerous
    # schemes. See reports/advisoryhub--001.md.
    ghsa_payload = dict(
        ghsa_payload,
        references=[
            "https://example.org/fix",
            {"type": "WEB", "url": "javascript:alert(document.cookie)"},
            {"type": "ARTICLE", "url": "data:text/html,<script>alert(1)</script>"},
        ],
    )
    project = make_project("p6")
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
    )
    apply_ghsa_to_advisory(advisory, ghsa_payload)
    urls = [r["url"] for r in advisory.references]
    # The clean https reference and the GHSA's own html_url survive…
    assert "https://example.org/fix" in urls
    assert ghsa_payload["html_url"] in urls
    # …but no dangerous-scheme reference is ever stored.
    assert not any(u.lower().startswith(("javascript:", "data:", "vbscript:")) for u in urls)


@pytest.mark.django_db
def test_translator_does_not_change_anything_outside_ghsa_readonly_fields(
    make_project, ghsa_payload
):
    project = make_project("p5")
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
    )
    pre = {
        "advisory_id": advisory.advisory_id,
        "state": advisory.state,
        "assigned_cve_id": advisory.assigned_cve_id,
        "project_id": advisory.project_id,
    }
    apply_ghsa_to_advisory(advisory, ghsa_payload)
    assert advisory.advisory_id == pre["advisory_id"]
    assert advisory.state == pre["state"]
    assert advisory.assigned_cve_id == pre["assigned_cve_id"]
    assert advisory.project_id == pre["project_id"]
