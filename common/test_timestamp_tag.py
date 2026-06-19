"""Unit tests for the ``{% timestamp %}`` template tag.

The tag renders the labelled-UTC ``<time>`` baseline that ``advisoryhub-time.js``
later localizes client-side. These tests pin the server contract: a machine-
readable instant in ``datetime``, a UTC-labelled visible baseline, the
``data-localize`` hook on plain timestamps (and its absence on relative ones),
and clean inline output (no stray whitespace before mid-sentence punctuation).
"""

from __future__ import annotations

from datetime import UTC, datetime

from django.utils.safestring import SafeString

from common.templatetags.advisoryhub_tags import timestamp

# A fixed aware instant. Test settings run with TIME_ZONE=UTC, so the server
# baseline renders in UTC and the ISO datetime carries the +00:00 offset.
DT = datetime(2026, 6, 5, 14, 30, tzinfo=UTC)


def test_plain_timestamp_is_localizable_utc_baseline():
    out = timestamp(DT)
    assert isinstance(out, SafeString)
    # Machine-readable instant with offset — what the client-side JS parses.
    assert 'datetime="2026-06-05T14:30:00+00:00"' in out
    # Hook for advisoryhub-time.js to rewrite into the viewer's timezone.
    assert "data-localize" in out
    # Always-correct, unambiguous visible baseline (JS-off / email fallback).
    assert ">2026-06-05 14:30 UTC</time>" in out
    # The server leaves the tooltip to the JS for plain timestamps.
    assert "title=" not in out


def test_relative_keeps_ago_text_and_labels_tooltip():
    out = timestamp(DT, relative=True)
    assert out.startswith("<time ")
    assert 'datetime="2026-06-05T14:30:00+00:00"' in out
    # Visible "N ago" text is timezone-agnostic and stays as rendered.
    assert "ago</time>" in out
    # Marked for the JS to localize the *tooltip* (text untouched); the server's
    # UTC-only title is the no-JS fallback the JS overrides with local + UTC.
    assert "data-localize" in out
    assert "data-relative" in out
    assert 'title="2026-06-05 14:30 UTC"' in out


def test_date_only_shows_date_and_labels_full_tooltip():
    out = timestamp(DT, date_only=True)
    assert out.startswith("<time ")
    # Machine-readable instant — what advisoryhub-time.js parses to localize.
    assert 'datetime="2026-06-05T14:30:00+00:00"' in out
    # Visible baseline is the calendar date only; the JS rewrites it to the
    # viewer's *local* date.
    assert ">2026-06-05</time>" in out
    # Marked for the JS to swap the text to the local date and the tooltip to the
    # full local datetime; the server seeds a full-UTC title as the no-JS fallback.
    assert "data-localize" in out
    assert "data-date-only" in out
    assert 'title="2026-06-05 14:30 UTC"' in out


def test_relative_wins_over_date_only_when_both_passed():
    # The two modes are mutually exclusive; relative takes precedence.
    out = timestamp(DT, relative=True, date_only=True)
    assert "data-relative" in out
    assert "data-date-only" not in out
    assert "ago</time>" in out


def test_css_class_is_placed_on_the_time_element():
    out = timestamp(DT, relative=True, css_class="notif-row__age")
    assert 'class="notif-row__age"' in out
    assert out.startswith('<time datetime="2026-06-05T14:30:00+00:00" class="notif-row__age"')


def test_output_has_no_surrounding_whitespace():
    # These <time> elements sit mid-sentence ("edited {ts})"); a trailing
    # newline from the partial would render as a stray space before punctuation.
    out = timestamp(DT)
    assert out == out.strip()
    assert out.startswith("<time") and out.endswith("</time>")


def test_falsy_value_renders_nothing():
    assert timestamp(None) == ""
    assert timestamp(None, relative=True) == ""
    assert timestamp(None, date_only=True) == ""
