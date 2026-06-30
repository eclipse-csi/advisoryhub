"""Template context processors.

``maintenance_mode`` exposes the cached maintenance snapshot plus whether
the *current viewer* is impacted, so ``base.html`` can render the banner
and flag the body for the button-disabling script. This is display-only —
enforcement lives in :class:`common.middleware.MaintenanceModeMiddleware`
(``INV-MAINT-1`` / ``INV-AUTH-1``).

``user_email_visibility`` sets the fail-closed default for whether the viewer
may see other users' emails in ``{% user_chip %}`` popovers: global admins, yes
(they're owners everywhere — this covers the admin console with no per-view
wiring); everyone else, no. Advisory-scoped views override it with the
per-advisory ``perms.can_see_user_emails`` so project security-team owners get
it on their own advisories (``INV-PRIVACY-4``).

``security_team_identity`` exposes the global security team's friendly display
name plus the admin-group slug, so templates can render
"Eclipse Foundation Security Team" wherever that group is named and detect its
row in group listings. Display-only (``INV-AUTH-1``).

``ghsa_feature`` exposes the ``GHSA_FEATURE_ENABLED`` flag so the Admin Console
sidebar can hide the GHSA section while the integration is dormant. Display-only
— every GHSA endpoint still re-checks the flag server-side.

``support_links`` resolves the footer help links from ``ADVISORYHUB_REPO_URL``
(report-an-issue + private-vulnerability-report paths are derived from it) and
``ADVISORYHUB_DISCUSSIONS_URL`` (ask-a-question). A blank base setting yields
``None`` for the affected link so ``base.html`` omits it rather than emitting a
malformed relative URL.

``app_version`` exposes the running application's version string. Not sensitive,
so it is returned unconditionally; ``base.html`` gates its display on
``user.is_global_admin`` (display-only, ``INV-AUTH-1``).
"""

from __future__ import annotations

import functools
import importlib.metadata
import tomllib
from pathlib import Path

from django.conf import settings
from django.http import HttpRequest

from common.constants import SECURITY_TEAM_DISPLAY_NAME


def user_email_visibility(request: HttpRequest) -> dict:
    from advisories import permissions as perms

    return {"viewer_can_see_emails": perms.is_global_admin(getattr(request, "user", None))}


def security_team_identity(request: HttpRequest) -> dict:
    return {
        "security_team_display_name": SECURITY_TEAM_DISPLAY_NAME,
        "admin_group_name": settings.OIDC_ADMIN_GROUP,
    }


def ghsa_feature(request: HttpRequest) -> dict:
    return {"ghsa_feature_enabled": getattr(settings, "GHSA_FEATURE_ENABLED", False)}


def support_links(request: HttpRequest) -> dict:
    repo = (getattr(settings, "ADVISORYHUB_REPO_URL", "") or "").rstrip("/")
    discussions = getattr(settings, "ADVISORYHUB_DISCUSSIONS_URL", "") or None
    return {
        "support_links": {
            "issues": f"{repo}/issues/new" if repo else None,
            "discussions": discussions,
            "security": f"{repo}/security/advisories/new" if repo else None,
        }
    }


@functools.cache
def _app_version() -> str:
    # pyproject.toml's [project] version is the canonical source dev/release.sh
    # bumps (matches the api/tests/test_openapi_spec.py drift guard and
    # dev/check_release_versions.sh). Installed-distribution metadata would be
    # authoritative when present, but the deployable image is a uv *virtual*
    # project (`uv sync --no-install-project`), so at runtime there is no
    # distribution to read — fall back to pyproject.toml, which is copied into
    # the image.
    try:
        return importlib.metadata.version("advisoryhub")
    except importlib.metadata.PackageNotFoundError:
        pass
    try:
        pyproject = Path(settings.BASE_DIR) / "pyproject.toml"
        return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return "unknown"


def app_version(request: HttpRequest) -> dict:
    return {"app_version": _app_version()}


def maintenance_mode(request: HttpRequest) -> dict:
    from admin_console.models import MaintenanceMode
    from advisories import permissions as perms
    from audit.services import redact_secrets

    snapshot = MaintenanceMode.current()
    is_admin = perms.is_global_admin(getattr(request, "user", None))
    # The banner is shown verbatim to everyone, so run the same redaction the
    # audit log uses (INV-AUDIT-2) — a token accidentally pasted into the
    # message must not leak in plaintext to every visitor.
    message = redact_secrets(snapshot["message"])
    return {
        "maintenance_mode": {
            "is_enabled": snapshot["is_enabled"],
            "message": message,
            "is_admin": is_admin,
            # True only for users who are actually paused — drives the
            # paused-variant banner and the body[data-maintenance-paused] hook.
            "paused": snapshot["is_enabled"] and not is_admin,
        }
    }
