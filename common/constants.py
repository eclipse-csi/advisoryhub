"""Shared display constants.

``SECURITY_TEAM_DISPLAY_NAME`` is the single source of truth for the
human-readable name of the global security team — members of the admin group
named by ``OIDC_ADMIN_GROUP`` (slug ``advisoryhub-security`` by default), who
hold owner on every advisory. Display-only (``INV-AUTH-1``): the group slug
remains the authoritative identifier; this is just how that group is *named*
to users in the chip seal, group listings, and error/review prose.
"""

from __future__ import annotations

SECURITY_TEAM_DISPLAY_NAME = "Eclipse Foundation Security Team"
