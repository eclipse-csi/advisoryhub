"""Unit tests for the ``event_pairs`` template filter.

Affected-range events are stored in the OSV single-key shape
(``{"introduced": "1.0.0"}``), but the detail page renders each event as a
chip with a separate kind and version. ``event_pairs`` bridges the two; before
it existed the template read ``ev.kind``/``ev.value`` off the OSV dict, which
have no such keys, so the kind rendered as ``?`` and the version was blank.
These tests pin the flattening contract.
"""

from __future__ import annotations

from advisories.templatetags.advisory_display import event_pairs


def test_event_pairs_flattens_single_key_dicts():
    events = [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]
    assert event_pairs(events) == [
        {"kind": "introduced", "value": "1.0.0"},
        {"kind": "fixed", "value": "1.2.0"},
    ]


def test_event_pairs_preserves_order():
    events = [{"introduced": "0"}, {"last_affected": "2.9.9"}]
    assert [p["kind"] for p in event_pairs(events)] == ["introduced", "last_affected"]


def test_event_pairs_handles_none_and_empty():
    assert event_pairs(None) == []
    assert event_pairs([]) == []


def test_event_pairs_skips_non_dict_entries():
    # Defensive: a malformed entry shouldn't blow up the detail page.
    assert event_pairs([{"introduced": "1.0.0"}, "garbage", None]) == [
        {"kind": "introduced", "value": "1.0.0"}
    ]
