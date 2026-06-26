"""Cross-cutting request middleware.

* :class:`RequestIDMiddleware` — request-id correlation.
* :class:`PermissionsPolicyMiddleware` — restrictive ``Permissions-Policy`` header.
* :class:`MaintenanceModeMiddleware` — server-side enforcement of the
  admin-toggled site-wide maintenance pause (``INV-MAINT-1``).
* :class:`HtmxMessagesMiddleware` — surface ``django.contrib.messages`` on HTMX
  responses as a client-side toast (``HX-Trigger``).
"""

from __future__ import annotations

import uuid

from django.contrib.messages import get_messages
from django.http import JsonResponse
from django.shortcuts import render
from django_htmx.http import trigger_client_event

from common.logging import reset_request_id, set_request_id
from common.rls import rls_principal


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
# actions.
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


class HtmxMessagesMiddleware:
    """Deliver ``django.contrib.messages`` to HTMX responses as toasts.

    Full-page responses already render pending messages through the
    ``#toast-data`` island in ``base.html``. An HTMX partial swap never
    re-renders ``base.html``, so a message added during such a request would sit
    in storage unseen until the next full page load. For an HTMX request whose
    response is a normal swap, we drain the message storage into an
    ``HX-Trigger: advisoryhub:messages`` header that ``advisoryhub-toast.js``
    renders (via :func:`django_htmx.http.trigger_client_event`, which safely
    merges with any pre-existing ``HX-Trigger`` value).

    Iterating the storage here marks it consumed, so ``MessageMiddleware`` —
    whose response phase runs *after* this one, since this middleware sits below
    it in ``MIDDLEWARE`` — re-stores an empty queue and the message never shows
    twice. This placement also requires ``request.htmx`` (set by
    ``HtmxMiddleware``, immediately above) to already be present.

    Responses that cause a *full reload* are deliberately left untouched so the
    message survives in storage and the reloaded page's island renders it: a 3xx
    redirect (htmx follows it), or an ``HX-Redirect`` / ``HX-Refresh`` /
    ``HX-Location`` directive (e.g. ``advisory_flag``'s 204 + ``HX-Refresh`` and
    the maintenance 503 + ``HX-Refresh``).
    """

    _FULL_RELOAD_HEADERS = ("HX-Redirect", "HX-Refresh", "HX-Location")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if not getattr(request, "htmx", False):
            return response
        if self._causes_full_reload(response):
            return response
        payload = [
            {"level": message.level_tag, "message": str(message.message)}
            for message in get_messages(request)
        ]
        if payload:
            trigger_client_event(response, "advisoryhub:messages", {"messages": payload})
        return response

    def _causes_full_reload(self, response) -> bool:
        if 300 <= response.status_code < 400:
            return True
        return any(header in response for header in self._FULL_RELOAD_HEADERS)


class RowLevelSecurityMiddleware:
    """Set the per-request row-level-security principal (``INV-CONF-2``).

    Runs after ``AuthenticationMiddleware`` (needs ``request.user``). Sets the
    ``advisoryhub.user_id`` / ``advisoryhub.is_admin`` session GUCs that the
    advisory RLS policy reads, then resets them — fail-closed — once the response
    is produced. A superuser DB role (the dev/CI bootstrap role) ignores RLS, so
    this has no enforcement effect there; under the production non-superuser role
    it is what scopes every query to the authenticated principal. See
    :mod:`common.rls`.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        with rls_principal(getattr(request, "user", None)):
            return self.get_response(request)
