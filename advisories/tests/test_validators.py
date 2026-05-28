"""Unit tests for ``advisories.validators.validate_affected`` event rules.

The OSV schema (vendored at ``publication/schemas/osv.upstream.json``) requires:

* at least one ``introduced`` event per range,
* ``fixed`` and ``last_affected`` to be mutually exclusive,
* each event object to have exactly one of ``introduced``, ``fixed``,
  ``last_affected``, or ``limit``.

The publication path validates against the schema, but the model-level
validator ensures these never reach a saved advisory in the first place.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from advisories.validators import validate_affected


def _affected(*events: dict[str, str]) -> list[dict]:
    return [
        {
            "package": {"name": "lib", "ecosystem": "npm"},
            "ranges": [{"type": "ECOSYSTEM", "events": list(events)}],
        }
    ]


def test_validate_affected_accepts_introduced_only():
    validate_affected(_affected({"introduced": "1.0.0"}))


def test_validate_affected_accepts_introduced_plus_fixed():
    validate_affected(_affected({"introduced": "1.0.0"}, {"fixed": "1.2.0"}))


def test_validate_affected_accepts_introduced_plus_last_affected():
    validate_affected(_affected({"introduced": "1.0.0"}, {"last_affected": "1.5.0"}))


def test_validate_affected_rejects_range_missing_introduced():
    with pytest.raises(ValidationError) as exc:
        validate_affected(_affected({"fixed": "1.1.0"}))
    assert "introduced" in str(exc.value)


def test_validate_affected_rejects_fixed_and_last_affected_in_same_range():
    with pytest.raises(ValidationError) as exc:
        validate_affected(
            _affected(
                {"introduced": "1.0.0"},
                {"fixed": "1.2.0"},
                {"last_affected": "1.5.0"},
            )
        )
    assert "mutually exclusive" in str(exc.value)


def test_validate_affected_rejects_event_with_unknown_kind():
    with pytest.raises(ValidationError) as exc:
        validate_affected(_affected({"introduced": "1.0.0"}, {"middle": "1.5.0"}))
    assert "must be one of" in str(exc.value)


def test_validate_affected_rejects_event_with_multiple_keys():
    bad = [
        {
            "package": {"name": "lib"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0.0", "fixed": "1.2.0"}],
                }
            ],
        }
    ]
    with pytest.raises(ValidationError) as exc:
        validate_affected(bad)
    assert "exactly one" in str(exc.value)


def test_validate_affected_rejects_event_with_empty_version():
    with pytest.raises(ValidationError) as exc:
        validate_affected(_affected({"introduced": ""}))
    assert "non-empty" in str(exc.value)


def test_validate_affected_allows_versions_only_entry():
    # No ranges → constraints don't apply.
    validate_affected([{"package": {"name": "lib"}, "versions": ["1.0.0"]}])
