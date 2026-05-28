from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from advisories.identifiers import (
    generate_advisory_id,
    is_valid_advisory_id,
)
from advisories.validators import validate_advisory_id

ALLOWED_CHARS = set("23456789cfghjmpqrvwx")


@pytest.mark.parametrize(
    "value",
    [
        "ECL-cf23-gh45-jm67",
        "ECL-2345-6789-cfgh",
        "ECL-jmpq-rvwx-2345",
        "ECL-xxxx-xxxx-xxxx",
    ],
)
def test_valid_ids(value):
    assert is_valid_advisory_id(value)
    validate_advisory_id(value)  # does not raise


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        "ecl-cf23-gh45-jm67",  # lowercase prefix
        "ECL-CFGH-2345-6789",  # uppercase suffix
        "ECL-cf23-gh45-jm6",  # too short
        "ECL-cf23-gh45-jm678",  # too long
        "ECL-cf23-gh45-jm67-2345",  # extra group
        "ECL-cf23-gh45",  # missing group
        "ECL-cf23_gh45_jm67",  # wrong separator
        "ECLcf23gh45jm67",
        "FOO-cf23-gh45-jm67",
        # Alphabet violations:
        "ECL-aaaa-bbbb-cccc",  # a, b not in alphabet
        "ECL-0000-2345-6789",  # 0 not in alphabet
        "ECL-1111-2345-6789",  # 1 not in alphabet
        "ECL-zzzz-2345-6789",  # z not in alphabet
        "ECL-dddd-2345-6789",  # d not in alphabet
        "ECL-eeee-2345-6789",  # e not in alphabet
    ],
)
def test_invalid_ids(value):
    assert not is_valid_advisory_id(value or "")
    with pytest.raises(ValidationError):
        validate_advisory_id(value or "")


def test_generated_ids_are_valid():
    seen = set()
    for _ in range(100):
        value = generate_advisory_id()
        assert is_valid_advisory_id(value)
        seen.add(value)
    # Vanishingly unlikely all 100 are equal
    assert len(seen) > 1


def test_generated_ids_use_only_restricted_alphabet():
    """Belt and braces: even if the regex changes, the generator alphabet
    must stay within the documented set."""
    structural = {"E", "C", "L", "-"}
    for _ in range(200):
        value = generate_advisory_id()
        payload = set(value) - structural
        assert payload <= ALLOWED_CHARS, f"{value} uses chars outside {ALLOWED_CHARS}"
