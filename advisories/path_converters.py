"""Custom URL path converter for advisory IDs.

Routing-time enforcement of the canonical advisory ID format so that
malformed IDs return 404 from the URL resolver instead of falling
through to a view that would do a DB lookup and then 404. The single
source of truth for the regex remains ``identifiers.ADVISORY_ID_RE``.
"""

from __future__ import annotations

from .identifiers import ADVISORY_ID_RE


class AdvisoryIdConverter:
    # Django wraps the pattern with its own anchors; strip ours.
    regex = ADVISORY_ID_RE.pattern.strip("^$")

    def to_python(self, value: str) -> str:
        return value

    def to_url(self, value: str) -> str:
        return value
