"""Tests for ``accounts.utils.mask_email`` (INV-PRIVACY-4)."""

from __future__ import annotations

import pytest

from accounts.utils import mask_email


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("alice@example.org", "a•••@example.org"),
        ("bob@example.org", "b•••@example.org"),
        # Single-char local part still masks to first-char + bullets.
        ("x@example.org", "x•••@example.org"),
        # Non-email strings (e.g. a group name) pass through untouched.
        ("advisoryhub-security", "advisoryhub-security"),
        ("", ""),
        (None, ""),
    ],
)
def test_mask_email(value, expected):
    assert mask_email(value) == expected


def test_mask_email_never_leaks_local_part_beyond_first_char():
    masked = mask_email("verysecret@example.org")
    assert masked == "v•••@example.org"
    assert "verysecret" not in masked
