"""Advisory identifier format and generation.

The format is intentionally opaque: ``ECL-`` followed by three groups of
four characters from a restricted, unambiguous alphabet, randomly
generated. There is no project hint inside the ID. Reasons:

- Project renames don't invalidate previously-issued advisory IDs or
  the publication-repo file paths that contain them.
- A leaked or guessed ID gives an attacker no information about which
  project it belongs to.
- The flat 12-char namespace (~4×10^15 possibilities) makes online
  guessing impractical.

The alphabet is ``23456789cfghjmpqrvwx`` (20 chars): digits 2–9 plus
twelve lowercase letters. Visually ambiguous characters are excluded
(``0/o``, ``1/i/l``, ``a/e``, ``b/d``, etc.) so IDs are safe to read
aloud, copy by hand, and transcribe from a printed page — important
because advisory IDs surface in emails, commit messages, OSV/CSAF file
paths, and the public publication repo.

Trade-off: humans can't tell which project an advisory concerns from
the ID alone. That's accepted; the project is always one click away on
the detail page and is part of every email/notification subject.
"""

from __future__ import annotations

import re
import secrets

ADVISORY_ID_RE = re.compile(r"^ECL(-[23456789cfghjmpqrvwx]{4}){3}$")
_ALPHABET = "23456789cfghjmpqrvwx"


def is_valid_advisory_id(value: str) -> bool:
    return bool(value) and bool(ADVISORY_ID_RE.match(value))


def generate_advisory_id() -> str:
    """Generate a syntactically valid advisory ID, e.g. ``ECL-cf23-gh45-jm67``.

    Uses :mod:`secrets` for unpredictable suffixes. Callers must check for
    DB collisions and retry — see ``Advisory._generate_unique_id``.
    """
    parts = ["".join(secrets.choice(_ALPHABET) for _ in range(4)) for _ in range(3)]
    return "ECL-" + "-".join(parts)
