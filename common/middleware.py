"""Cross-cutting request middleware.

* :class:`RequestIDMiddleware` — request-id correlation.
* :class:`PermissionsPolicyMiddleware` — restrictive ``Permissions-Policy`` header.
* :class:`MaintenanceModeMiddleware` — server-side enforcement of the
  admin-toggled site-wide maintenance pause (``INV-MAINT-1``).
"""

from __future__ import annotations

import uuid

from django.http import JsonResponse
from django.shortcuts import render

from common.logging import reset_request_id, set_request_id


class RequestIDMiddleware:
    HEADER = "HTTP_X_REQUEST_ID"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        rid = request.META.get(self.HEADER) or uuid.uuid4().hex
        request.request_id = rid
        token = set_request_id(rid)
        try:
            response = self.get_response(request)
        finally:
            reset_request_id(token)
        response["X-Request-ID"] = rid
        return response


class PermissionsPolicyMiddleware:
    """Emit a restrictive ``Permissions-Policy`` header.

    Django ships no default for this header. AdvisoryHub uses none of these
    powerful browser features, so denying them outright is zero-risk hardening
    that shrinks the attack surface for any injected or embedded content. It
    complements the CSP (django-csp) and the ``X-Frame-Options: DENY`` /
    ``frame-ancestors`` clickjacking guard.
    """

    HEADER = "Permissions-Policy"
    POLICY = (
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), "
        "encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), midi=(), payment=(), usb=()"
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault(self.HEADER, self.POLICY)
        return response


# HTTP methods that never mutate server state. Maintenance mode pauses
# *actions*, not reading — so non-admins keep browsing (and see the banner)
# while every write is refused.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

# Path prefixes that stay fully usable during maintenance even for non-admins
# and even for unsafe methods. These are auth plumbing (so anyone can sign in
# or out, and an admin can authenticate to lift the pause), operational
# probes/assets, and external machine callbacks — never user application
# actions. NB: /django-admin/ is deliberately NOT here — it is governed by the
# same is_global_admin gate as everything else, so a session whose stale
# is_staff/is_superuser flag outlived its admin-group membership (the columns
# only re-sync at OIDC login, INV-OIDC-3) cannot mutate data through Django
# admin while paused.
_EXEMPT_PREFIXES = (
    "/oidc/",  # authenticate, callback, logout (POST), step-up
    "/healthz",
    "/readyz",
    "/metrics",
    "/static/",
    # Inbound GitHub App webhook: HMAC-authenticated machine traffic, not a
    # user action. Blocking it would silently drop deliveries GitHub stops
    # retrying after its window; instead we keep recording them (the row +
    # audit) and let the Celery worker — paused independently — do the work.
    "/ghsa/webhook/",
)


class MaintenanceModeMiddleware:
    """Refuse state-changing requests from non-admins while paused.

    The switch is read through the cached :meth:`MaintenanceMode.current`
    snapshot, so the common (mode-off) case is a single cache hit. Global
    admins (members of ``settings.OIDC_ADMIN_GROUP``) are never paused; the
    banner and disabled buttons are display-only, so this middleware is the
    actual authority that makes "everyone but admins is paused" true.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self._should_block(request):
            return self._blocked_response(request)
        return self.get_response(request)

    def _should_block(self, request) -> bool:
        # Cheapest checks first: safe methods and exempt paths never block,
        # regardless of mode, so the cache read is skipped for most reads.
        if request.method in _SAFE_METHODS:
            return False
        path = request.path
        if any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return False

        # Lazy imports: the middleware module is imported at startup before the
        # app registry settles, and to keep the auth decision routed through
        # the canonical predicate (INV-AUTH-1 / INV-OIDC-2).
        from admin_console.models import MaintenanceMode
        from advisories import permissions as perms

        # Authoritative (uncached) read: the pause is an authz decision and
        # must be coherent across workers the instant it is toggled.
        if not MaintenanceMode.is_paused():
            return False
        # Admins act normally; everyone else (incl. anonymous) is paused.
        return not perms.is_global_admin(getattr(request, "user", None))

    def _blocked_response(self, request):
        detail = "AdvisoryHub is in maintenance mode. Actions are temporarily paused."
        if request.path.startswith("/api/"):
            response = JsonResponse({"detail": detail}, status=503)
        else:
            response = render(request, "maintenance/blocked.html", status=503)
            # HTMX swaps only on 2xx; force a full reload so the blocked user
            # lands on a page that shows the maintenance banner + disabled UI.
            if getattr(request, "htmx", False):
                response["HX-Refresh"] = "true"
        response["Retry-After"] = "3600"
        return response
