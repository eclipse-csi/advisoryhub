"""Unit tests for the shared line+word text-diff helper.

Pure function — no DB. Drives both the description-history and
comment-history drawers via ``templates/common/_diff_chunks.html``.
"""

from __future__ import annotations

from common.text_diff import text_diff


def test_empty_inputs():
    assert text_diff("", "") == []


def test_pure_insertion():
    chunks = text_diff("line one", "line one\nline two")
    kinds = [c["kind"] for c in chunks]
    assert "insert" in kinds
    inserts = [c for c in chunks if c["kind"] == "insert"]
    assert inserts[0]["lines"] == ["line two"]


def test_pure_deletion():
    chunks = text_diff("line one\nline two", "line one")
    kinds = [c["kind"] for c in chunks]
    assert "delete" in kinds
    deletes = [c for c in chunks if c["kind"] == "delete"]
    assert deletes[0]["lines"] == ["line two"]


def test_word_level_replace_single_line():
    chunks = text_diff(
        "An attacker may bypass authentication.",
        "An unauthenticated attacker may bypass authentication.",
    )
    replace_chunks = [c for c in chunks if c["kind"] == "replace"]
    assert replace_chunks, f"expected a replace chunk in {chunks!r}"
    pair = replace_chunks[0]["pairs"][0]

    after_inserts = [r["text"] for r in pair["after_runs"] if r["op"] == "insert"]
    assert any("unauthenticated" in t for t in after_inserts)
    # The unchanged words appear as equal runs on both sides.
    before_equal = "".join(r["text"] for r in pair["before_runs"] if r["op"] == "equal")
    after_equal = "".join(r["text"] for r in pair["after_runs"] if r["op"] == "equal")
    assert "attacker" in before_equal and "attacker" in after_equal


def test_replace_multi_line_block():
    before = "first changed line\nsecond changed line"
    after = "first replaced line\nsecond replaced line"
    chunks = text_diff(before, after)
    replace_chunks = [c for c in chunks if c["kind"] == "replace"]
    assert replace_chunks
    # Both lines should be paired (same line count on each side).
    assert len(replace_chunks[0]["pairs"]) == 2
    for pair in replace_chunks[0]["pairs"]:
        assert pair["before_runs"] is not None
        assert pair["after_runs"] is not None


def test_unchanged_lines_preserved_as_equal_chunks():
    chunks = text_diff(
        "kept line\nbefore line",
        "kept line\nafter line",
    )
    equal = [c for c in chunks if c["kind"] == "equal"]
    assert any("kept line" in c["lines"] for c in equal)
