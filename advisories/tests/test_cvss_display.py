"""Unit tests for the ``cvss_display`` template filter.

The filter renders the compact "version + base score" severity chip on the
advisory detail page, deriving the numeric score and qualitative level from the
stored OSV severity vector via the ``cvss`` library (the same engine the
publication CVE builder uses). These tests pin that contract — including the
graceful fallbacks for Ubuntu entries and unparseable vectors — so the severity
never silently disappears from the metadata card.
"""

from __future__ import annotations

from advisories.templatetags.advisory_display import cvss_display


def test_cvss_v3_vector_scores_and_buckets():
    out = cvss_display({"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"})
    assert out == {
        "version": "CVSS 3.1",
        "score": "7.5",
        "level": "high",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    }


def test_cvss_v3_full_impact_is_critical():
    out = cvss_display({"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert out["score"] == "9.8"
    assert out["level"] == "critical"


def test_cvss_v4_vector():
    out = cvss_display(
        {
            "type": "CVSS_V4",
            "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        }
    )
    assert out["version"] == "CVSS 4.0"
    assert out["level"] == "critical"


def test_cvss_v2_vector():
    out = cvss_display({"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"})
    assert out["version"] == "CVSS 2.0"
    assert out["score"] == "7.5"


def test_ubuntu_entry_passes_word_through_with_no_descriptor():
    out = cvss_display({"type": "Ubuntu", "score": "high"})
    # No version descriptor — Ubuntu shows just its severity word.
    assert out == {"version": "", "score": "high", "level": "high", "vector": "high"}


def test_unparseable_vector_keeps_string_with_empty_score():
    out = cvss_display({"type": "CVSS_V3", "score": "not-a-vector"})
    assert out["score"] == ""  # template renders an em dash
    assert out["level"] == "none"
    assert out["vector"] == "not-a-vector"  # still copyable / shown on hover


def test_empty_or_non_dict_returns_none():
    assert cvss_display({"type": "CVSS_V3", "score": ""}) is None
    assert cvss_display({}) is None
    assert cvss_display(None) is None
    assert cvss_display("CVSS:3.1/AV:N") is None
