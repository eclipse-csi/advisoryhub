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
"""

from __future__ import annotations

from django.http import HttpRequest


def user_email_visibility(request: HttpRequest) -> dict:
    from advisories import permissions as perms

    return {"viewer_can_see_emails": perms.is_global_admin(getattr(request, "user", None))}


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
