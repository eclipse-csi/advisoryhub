"""Unit tests for the advisory sub-forms, formsets, and JSON assembly."""

from __future__ import annotations

from advisories.form_assembly import assemble_json
from advisories.forms import (
    AffectedFormSet,
    AliasFormSet,
    CreditForm,
    CreditFormSet,
    CweIdForm,
    CweIdFormSet,
    EventForm,
    EventFormSet,
    ReferenceForm,
    ReferenceFormSet,
    SeverityForm,
    SeverityFormSet,
)


def _mgmt(prefix: str, total: int, initial: int = 0) -> dict[str, str]:
    return {
        f"{prefix}-TOTAL_FORMS": str(total),
        f"{prefix}-INITIAL_FORMS": str(initial),
        f"{prefix}-MIN_NUM_FORMS": "0",
        f"{prefix}-MAX_NUM_FORMS": "1000",
    }


# ---- sub-form validation ---------------------------------------------------


def test_reference_form_rejects_empty_url():
    form = ReferenceForm(data={"type": "WEB", "url": ""})
    assert not form.is_valid()
    assert "url" in form.errors


def test_reference_form_accepts_bare_domain():
    # assume_scheme="https" turns example.com into https://example.com
    form = ReferenceForm(data={"type": "WEB", "url": "example.com"})
    assert form.is_valid(), form.errors
    assert form.cleaned_data["url"] == "https://example.com"


def test_event_form_rejects_empty_value():
    form = EventForm(data={"kind": "fixed", "value": ""})
    assert not form.is_valid()
    assert "value" in form.errors


def _event_formset(*rows: tuple[str, str], prefix: str = "events"):
    data = _mgmt(prefix, total=len(rows), initial=len(rows))
    for i, (kind, value) in enumerate(rows):
        data[f"{prefix}-{i}-kind"] = kind
        data[f"{prefix}-{i}-value"] = value
    return EventFormSet(data, prefix=prefix)


def test_event_formset_accepts_introduced_only():
    fs = _event_formset(("introduced", "1.0.0"))
    assert fs.is_valid(), fs.errors


def test_event_formset_accepts_introduced_plus_fixed():
    fs = _event_formset(("introduced", "1.0.0"), ("fixed", "1.2.0"))
    assert fs.is_valid(), fs.errors


def test_event_formset_rejects_when_introduced_missing():
    fs = _event_formset(("fixed", "1.2.0"))
    assert not fs.is_valid()
    assert any("Introduced" in str(err) for err in fs.non_form_errors())


def test_event_formset_rejects_fixed_and_last_affected_together():
    fs = _event_formset(
        ("introduced", "1.0.0"),
        ("fixed", "1.2.0"),
        ("last_affected", "1.5.0"),
    )
    assert not fs.is_valid()
    assert any("mutually exclusive" in str(err) for err in fs.non_form_errors())


def test_event_formset_empty_is_valid():
    # An outer affected row with no events at all (e.g. a versions-only entry)
    # must not trigger the introduced-required check.
    fs = EventFormSet(_mgmt("events", total=0), prefix="events")
    assert fs.is_valid(), fs.errors


def test_event_formset_ignores_deleted_rows():
    # If the only non-introduced event is also DELETEd, the surviving rows
    # still pass the introduced-required check.
    prefix = "events"
    data = _mgmt(prefix, total=2, initial=2)
    data[f"{prefix}-0-kind"] = "introduced"
    data[f"{prefix}-0-value"] = "1.0.0"
    data[f"{prefix}-1-kind"] = "fixed"
    data[f"{prefix}-1-value"] = "1.2.0"
    data[f"{prefix}-1-DELETE"] = "on"
    fs = EventFormSet(data, prefix=prefix)
    assert fs.is_valid(), fs.errors


def test_severity_form_rejects_unknown_type():
    form = SeverityForm(data={"type": "CVSS_V5", "score": "x"})
    assert not form.is_valid()
    assert "type" in form.errors


def test_severity_form_accepts_ubuntu_with_enum_score():
    form = SeverityForm(data={"type": "Ubuntu", "score": "", "score_ubuntu": "low"})
    assert form.is_valid(), form.errors
    # clean() merges score_ubuntu into score so downstream JSON sees one value.
    assert form.cleaned_data["score"] == "low"


def test_severity_form_rejects_ubuntu_without_enum_score():
    form = SeverityForm(data={"type": "Ubuntu", "score": "", "score_ubuntu": ""})
    assert not form.is_valid()
    assert "score_ubuntu" in form.errors


def test_severity_form_rejects_ubuntu_with_freeform_score():
    # Submitting a CVSS-style score for Ubuntu should fail because the
    # JS-driven UI hides the cvss input but if a script-disabled client
    # somehow submits it, the row's score_ubuntu still has to be set.
    form = SeverityForm(data={"type": "Ubuntu", "score": "CVSS:3.1/AV:N/...", "score_ubuntu": ""})
    assert not form.is_valid()
    assert "score_ubuntu" in form.errors


def test_severity_form_rejects_ubuntu_score_outside_enum():
    # The ChoiceField rejects anything not in the enum.
    form = SeverityForm(data={"type": "Ubuntu", "score_ubuntu": "extreme"})
    assert not form.is_valid()
    assert "score_ubuntu" in form.errors


def test_reference_form_accepts_git_type():
    form = ReferenceForm(data={"type": "GIT", "url": "https://example.org/repo"})
    assert form.is_valid(), form.errors


def test_credit_form_accepts_osv_enum_value():
    form = CreditForm(data={"name": "Alice", "type": "REMEDIATION_DEVELOPER"})
    assert form.is_valid(), form.errors
    assert form.cleaned_data["type"] == "REMEDIATION_DEVELOPER"


def test_credit_form_rejects_unknown_type():
    form = CreditForm(data={"name": "Alice", "type": "MAINTAINER"})
    assert not form.is_valid()
    assert "type" in form.errors


def test_credit_form_allows_blank_type():
    form = CreditForm(data={"name": "Alice", "type": ""})
    assert form.is_valid(), form.errors
    assert form.cleaned_data["type"] == ""


def test_cwe_form_uppercases_and_requires_prefix():
    form = CweIdForm(data={"value": "cwe-79"})
    assert form.is_valid(), form.errors
    assert form.cleaned_data["value"] == "CWE-79"

    bad = CweIdForm(data={"value": "79"})
    assert not bad.is_valid()


def test_cwe_form_rejects_unknown_id():
    # CWE-9999999 will not exist in any MITRE release for the foreseeable
    # future; the strict validator must reject it instead of letting a
    # made-up id slip through into the JSON field.
    form = CweIdForm(data={"value": "CWE-9999999"})
    assert not form.is_valid()
    assert "value" in form.errors


def test_cwe_form_accepts_well_known_ids():
    # Spot-check a handful of common ids so a stale catalog regresses loudly.
    for cwe in ("CWE-79", "CWE-89", "CWE-22", "CWE-352"):
        form = CweIdForm(data={"value": cwe})
        assert form.is_valid(), (cwe, form.errors)


def test_validate_cwe_ids_rejects_unknown_id():
    # The model-level validator is invoked in full_clean even when the
    # advisory is built outside the formset path (e.g. seed_demo, imports).
    import pytest
    from django.core.exceptions import ValidationError

    from advisories.validators import validate_cwe_ids

    validate_cwe_ids(["CWE-79"])  # known — must not raise
    with pytest.raises(ValidationError):
        validate_cwe_ids(["CWE-79", "CWE-9999999"])


# ---- formset DELETE / TOTAL handling ---------------------------------------


def test_alias_formset_skips_deleted_row():
    data = {
        **_mgmt("aliases", total=2, initial=2),
        "aliases-0-value": "CVE-2025-1",
        "aliases-0-DELETE": "on",
        "aliases-1-value": "CVE-2025-2",
    }
    fs = AliasFormSet(data, prefix="aliases")
    assert fs.is_valid(), fs.errors
    kept = [f.cleaned_data["value"] for f in fs.forms if not f.cleaned_data.get("DELETE")]
    assert kept == ["CVE-2025-2"]


def test_credit_formset_collects_all_rows():
    data = {
        **_mgmt("credits", total=2),
        "credits-0-name": "Alice",
        "credits-0-type": "REPORTER",
        "credits-1-name": "Bob",
        "credits-1-type": "",
    }
    fs = CreditFormSet(data, prefix="credits")
    assert fs.is_valid(), fs.errors


# ---- JSON assembly ---------------------------------------------------------


def _build_assembled(post: dict) -> dict[str, list]:
    formsets = {
        "aliases": AliasFormSet(post, prefix="aliases"),
        "cwe_ids": CweIdFormSet(post, prefix="cwe_ids"),
        "references": ReferenceFormSet(post, prefix="references"),
        "severity": SeverityFormSet(post, prefix="severity"),
        "credits": CreditFormSet(post, prefix="credits"),
        "affected": AffectedFormSet(post, prefix="affected"),
    }
    for fs in formsets.values():
        assert fs.is_valid(), fs.errors
    n_outer = formsets["affected"].total_form_count()
    event_formsets = []
    for i in range(n_outer):
        efs = EventFormSet(post, prefix=f"affected-{i}-events")
        assert efs.is_valid(), efs.errors
        event_formsets.append(efs)
    return assemble_json(formsets, event_formsets)


def test_assemble_empty_formsets_yields_empty_lists():
    payload = {}
    for prefix in ("aliases", "cwe_ids", "references", "severity", "credits", "affected"):
        payload.update(_mgmt(prefix, total=0))
    out = _build_assembled(payload)
    assert out == {
        "aliases": [],
        "cwe_ids": [],
        "references": [],
        "severity": [],
        "credits": [],
        "affected": [],
    }


def test_assemble_full_affected_with_nested_events():
    payload = {
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 1),
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "npm",
        "affected-0-range_type": "ECOSYSTEM",
        "affected-0-versions": "",
        **_mgmt("affected-0-events", 2),
        "affected-0-events-0-kind": "introduced",
        "affected-0-events-0-value": "1.0.0",
        "affected-0-events-1-kind": "fixed",
        "affected-0-events-1-value": "1.2.0",
    }
    out = _build_assembled(payload)
    assert out["affected"] == [
        {
            "package": {"name": "lib", "ecosystem": "npm"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.0.0"},
                        {"fixed": "1.2.0"},
                    ],
                }
            ],
        }
    ]


def test_assemble_affected_with_purl():
    payload = {
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 1),
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "Maven",
        "affected-0-package_purl": "pkg:maven/org.example/lib@1.0.0",
        "affected-0-range_type": "ECOSYSTEM",
        "affected-0-versions": "",
        **_mgmt("affected-0-events", 2),
        "affected-0-events-0-kind": "introduced",
        "affected-0-events-0-value": "1.0.0",
        "affected-0-events-1-kind": "fixed",
        "affected-0-events-1-value": "1.1.0",
    }
    out = _build_assembled(payload)
    assert out["affected"] == [
        {
            "package": {
                "name": "lib",
                "ecosystem": "Maven",
                "purl": "pkg:maven/org.example/lib@1.0.0",
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0.0"}, {"fixed": "1.1.0"}],
                }
            ],
        }
    ]


def test_assemble_affected_purl_omitted_when_blank():
    payload = {
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 1),
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "",
        "affected-0-package_purl": "",
        "affected-0-range_type": "",
        "affected-0-versions": "1.0.0",
        **_mgmt("affected-0-events", 0),
    }
    out = _build_assembled(payload)
    # purl key is absent (not "" — keeps the JSON minimal).
    assert out["affected"] == [{"package": {"name": "lib"}, "versions": ["1.0.0"]}]


def test_assemble_versions_only_affected():
    payload = {
        **_mgmt("aliases", 0),
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 1),
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "",
        "affected-0-range_type": "",
        "affected-0-versions": "1.0.0\n1.0.1\n",
        **_mgmt("affected-0-events", 0),
    }
    out = _build_assembled(payload)
    assert out["affected"] == [{"package": {"name": "lib"}, "versions": ["1.0.0", "1.0.1"]}]


def test_assemble_deletes_skipped():
    payload = {
        **_mgmt("aliases", 2, initial=2),
        "aliases-0-value": "CVE-1",
        "aliases-0-DELETE": "on",
        "aliases-1-value": "CVE-2",
        **_mgmt("cwe_ids", 0),
        **_mgmt("references", 0),
        **_mgmt("severity", 0),
        **_mgmt("credits", 0),
        **_mgmt("affected", 0),
    }
    out = _build_assembled(payload)
    assert out["aliases"] == ["CVE-2"]


# ---- ReferenceForm + SeverityForm round-trip via formset -------------------


def test_reference_formset_invalid_url_marks_row():
    # Pick a non-default type so the row counts as "changed" — Django formsets
    # treat fully-default rows as empty and skip per-field validation.
    data = {
        **_mgmt("references", 1),
        "references-0-type": "ADVISORY",
        "references-0-url": "",
    }
    fs = ReferenceFormSet(data, prefix="references")
    assert not fs.is_valid()
    assert "url" in fs.forms[0].errors


def test_severity_formset_accepts_well_formed_cvss():
    data = {
        **_mgmt("severity", 1),
        "severity-0-type": "CVSS_V3",
        "severity-0-score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    fs = SeverityFormSet(data, prefix="severity")
    assert fs.is_valid(), fs.errors
