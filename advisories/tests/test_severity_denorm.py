"""The denormalised ``Advisory.severity_level`` / ``severity_score`` columns.

These mirror the worst ``severity`` entry so the advisory list can filter, sort,
and badge by severity without parsing CVSS vectors per row. They're derived —
recomputed in :meth:`Advisory.save` whenever ``severity`` is written, and
deliberately kept out of :meth:`Advisory.to_payload` so they are never versioned.
"""

from __future__ import annotations

import pytest

from advisories.models import Advisory
from advisories.severity import effective_severity

# Scores pinned by advisories/tests/test_cvss_display.py.
_CVSS_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 critical
_CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5 high


# --- pure helper ----------------------------------------------------------- #


def test_effective_severity_picks_worst_entry():
    level, score = effective_severity(
        [
            {"type": "Ubuntu", "score": "low"},
            {"type": "CVSS_V3", "score": _CVSS_CRIT},
        ]
    )
    assert level == "critical"
    assert score == pytest.approx(9.8)


def test_effective_severity_prefers_scored_entry_within_a_level():
    """At the same level, the entry carrying a numeric score wins (so the badge
    can show a number rather than an Ubuntu word)."""
    level, score = effective_severity(
        [
            {"type": "Ubuntu", "score": "high"},
            {"type": "CVSS_V3", "score": _CVSS_HIGH},
        ]
    )
    assert level == "high"
    assert score == pytest.approx(7.5)


def test_effective_severity_negligible_folds_to_low():
    assert effective_severity([{"type": "Ubuntu", "score": "negligible"}]) == ("low", None)


def test_effective_severity_empty_is_unscored():
    assert effective_severity([]) == ("none", None)
    assert effective_severity([{"type": "CVSS_V3", "score": "not-a-vector"}]) == ("none", None)


# --- save-time sync -------------------------------------------------------- #


@pytest.mark.django_db
def test_save_populates_denormalised_severity(make_project):
    adv = Advisory.objects.create(
        project=make_project("sev-a"),
        summary="x",
        severity=[{"type": "CVSS_V3", "score": _CVSS_CRIT}],
    )
    adv.refresh_from_db()
    assert adv.severity_level == "critical"
    assert adv.severity_score == pytest.approx(9.8)


@pytest.mark.django_db
def test_editing_severity_updates_denormalised(make_project):
    adv = Advisory.objects.create(
        project=make_project("sev-b"),
        summary="x",
        severity=[{"type": "CVSS_V3", "score": _CVSS_CRIT}],
    )
    adv.severity = [{"type": "CVSS_V3", "score": _CVSS_HIGH}]
    adv.save()
    adv.refresh_from_db()
    assert adv.severity_level == "high"
    assert adv.severity_score == pytest.approx(7.5)


@pytest.mark.django_db
def test_ubuntu_only_advisory_has_level_but_no_score(make_project):
    adv = Advisory.objects.create(
        project=make_project("sev-c"),
        summary="x",
        severity=[{"type": "Ubuntu", "score": "medium"}],
    )
    adv.refresh_from_db()
    assert adv.severity_level == "medium"
    assert adv.severity_score is None


@pytest.mark.django_db
def test_partial_save_without_severity_leaves_denormalised(make_project):
    """A targeted ``update_fields`` save that doesn't name ``severity`` must not
    recompute the denormalised columns (and doesn't force-load severity)."""
    adv = Advisory.objects.create(
        project=make_project("sev-d"),
        summary="x",
        severity=[{"type": "CVSS_V3", "score": _CVSS_CRIT}],
    )
    adv.summary = "y"
    adv.severity = []  # changed in memory but not persisted (not in update_fields)
    adv.save(update_fields=["summary", "modified_at"])
    adv.refresh_from_db()
    assert adv.severity_level == "critical"
    assert adv.severity_score == pytest.approx(9.8)
    assert adv.severity == [{"type": "CVSS_V3", "score": _CVSS_CRIT}]


@pytest.mark.django_db
def test_denormalised_severity_absent_from_payload(make_project):
    adv = Advisory.objects.create(
        project=make_project("sev-e"),
        summary="x",
        severity=[{"type": "CVSS_V3", "score": _CVSS_CRIT}],
    )
    payload = adv.to_payload()
    assert "severity" in payload
    assert "severity_level" not in payload
    assert "severity_score" not in payload
