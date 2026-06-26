"""Canonical OSV ecosystem names + acceptance check.

Single source of truth shared by:

* :mod:`advisories.forms` — powers the ``<datalist>`` autocomplete on the
  ``package_ecosystem`` input, and
* :func:`advisories.validators.validate_affected` — rejects an invalid value on
  every ``full_clean()`` so a bad ecosystem can never reach the publication task
  (where it would otherwise fail late against the OSV JSON schema).

Kept in lock-step with the vendored schema's ``ecosystemWithSuffix`` pattern
(``publication/schemas/osv.upstream.json``) by a drift-guard test in
``publication/tests/test_osv.py``.

This module is a leaf: it imports nothing from the rest of the app, so both
``forms`` and ``validators`` can import it without a cycle (the app import chain
is forms -> models -> validators, and ``advisories`` must never import from
``publication``).
"""

from __future__ import annotations

import re
from typing import Any

# Verbatim upstream identifiers (OSV copies them straight through). The 46 base
# ecosystems from the (tag-pinned) schema's ``ecosystemName`` enum, plus ``GIT``
# which the ``ecosystemWithSuffix`` pattern additionally allows. Order matches the
# schema so the drift-guard test is a trivial ordered equality — keep this list in
# lock-step with publication/schemas/osv.upstream.json (pinned in SCHEMAS.VERSION).
OSV_ECOSYSTEMS: tuple[str, ...] = (
    "AlmaLinux",
    "Alpaquita",
    "Alpine",
    "Android",
    "BellSoft Hardened Containers",
    "Bioconductor",
    "Bitnami",
    "Chainguard",
    "CleanStart",
    "ConanCenter",
    "CRAN",
    "crates.io",
    "Debian",
    "Docker Hardened Images",
    "Echo",
    "FreeBSD",
    "GHC",
    "GitHub Actions",
    "Go",
    "Hackage",
    "Hex",
    "Julia",
    "Kubernetes",
    "Linux",
    "Mageia",
    "Maven",
    "MinimOS",
    "npm",
    "NuGet",
    "opam",
    "openEuler",
    "openSUSE",
    "OSS-Fuzz",
    "Packagist",
    "Photon OS",
    "Pub",
    "PyPI",
    "Red Hat",
    "Rocky Linux",
    "Root",
    "RubyGems",
    "SUSE",
    "SwiftURL",
    "Ubuntu",
    "VSCode",
    "Wolfi",
    "GIT",
)

# Mirror the schema's ``ecosystemWithSuffix``: a base name, optionally followed
# by ``:<suffix>`` (e.g. ``Debian:11``). Built from OSV_ECOSYSTEMS via re.escape
# so names with regex metacharacters ("crates.io") and spaces ("Red Hat")
# match literally and the tuple above stays the single source of truth.
_ECOSYSTEM_RE = re.compile(
    r"(?:" + "|".join(re.escape(name) for name in OSV_ECOSYSTEMS) + r")(?::.+)?"
)


def is_valid_ecosystem(value: Any) -> bool:
    """True iff ``value`` is an accepted OSV ecosystem (base, or ``base:suffix``).

    Returns ``False`` for empty / non-string input — presence is each caller's
    decision (the form field is ``required``; the validator rejects a missing
    value with its own message).
    """
    return isinstance(value, str) and _ECOSYSTEM_RE.fullmatch(value) is not None
