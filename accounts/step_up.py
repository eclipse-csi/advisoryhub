"""Step-up authentication for publish.

Publishing pushes to a public Git repo, so we ask for a fresh OIDC
re-authentication right before the action regardless of how long the
session has been alive. The flow:

1. Publish view calls ``require_step_up_or_redirect(request, next=...)``.
2. If ``request.session["step_up_auth_at"]`` is fresh (within
   ``STEP_UP_MAX_AGE_SECONDS``), the view proceeds.
3. Otherwise, we mark the session ``step_up_pending`` and redirect
   through ``/oidc/step-up/`` — a thin subclass of mozilla-django-oidc's
   request view that adds ``prompt=login&max_age=0`` so the IdP forces
   re-entry of credentials.
4. On successful OIDC callback, the ``user_logged_in`` signal handler
   records the timestamp and clears the pending flag, then we redirect
   the user back to ``next``.

Why a session-scoped timestamp and not ``user.last_login``: a normal
sign-in updates ``last_login``, so basing step-up on it would let a
2-hour-old session pass the freshness check. The session-scoped marker
is set *only* when the OIDC flow ran with our ``prompt=login`` flag.
"""

from __future__ import annotations

import time
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.http import HttpResponseRedirect
from django.urls import reverse
from mozilla_django_oidc.views import OIDCAuthenticationRequestView

STEP_UP_AGE_KEY = "step_up_auth_at"
STEP_UP_FLAG_KEY = "step_up_pending"
STEP_UP_NEXT_KEY = "step_up_next"


def step_up_max_age() -> int:
    return getattr(settings, "STEP_UP_MAX_AGE_SECONDS", 300)


def step_up_required() -> bool:
    return getattr(settings, "STEP_UP_REQUIRED", True)


def is_step_up_fresh(request) -> bool:
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return False
    ts = request.session.get(STEP_UP_AGE_KEY, 0)
    if not ts:
        return False
    return (time.time() - ts) <= step_up_max_age()


def require_step_up_or_redirect(request, next_url: str) -> HttpResponseRedirect | None:
    """If step-up is stale, return a redirect to start the flow.

    Returns ``None`` when the caller may proceed.
    """
    if not step_up_required():
        return None
    if is_step_up_fresh(request):
        return None
    request.session[STEP_UP_FLAG_KEY] = True
    request.session[STEP_UP_NEXT_KEY] = next_url
    request.session.modified = True
    return HttpResponseRedirect(reverse("step_up_initiate"))


class StepUpAuthRequestView(OIDCAuthenticationRequestView):
    """OIDC authorize-init view that forces re-entry of credentials.

    Adds ``prompt=login`` and ``max_age=0`` so the IdP cannot satisfy
    the request from a cached session — the user must produce
    credentials right now.
    """

    def get(self, request):
        request.session[STEP_UP_FLAG_KEY] = True
        request.session.modified = True
        return super().get(request)

    def get_extra_params(self, request):
        params = super().get_extra_params(request)
        params["prompt"] = "login"
        params["max_age"] = "0"
        return params


def step_up_callback_redirect(request) -> str:
    """After step-up, send the user back to the page they tried to publish from."""
    return request.session.pop(STEP_UP_NEXT_KEY, "/") or "/"


@receiver(user_logged_in)
def record_step_up_on_login(sender, request, user, **kwargs):  # noqa: ARG001
    """When OIDC login completes, audit it and (if a step-up flow) stamp the session.

    The pending flag is set by ``StepUpAuthRequestView`` (or by
    ``require_step_up_or_redirect``) before the redirect; we only flip
    it into a fresh timestamp if it was set, so an ordinary sign-in
    does NOT satisfy the step-up freshness check.

    This is the single ``user_logged_in`` receiver, so it also writes the
    authentication access-log entry: ``auth.step_up_completed`` for a step-up
    re-auth, ``auth.login`` for an ordinary sign-in. Reading the pending flag
    once here (rather than from a second receiver) avoids racing the ``pop``.
    Routed to the ephemeral access log via ``record_from_request`` (IP +
    user-agent captured); ``actor`` is passed explicitly because ``request.user``
    is not populated when the signal is sent manually (as in tests).
    """
    if not request:
        return
    from audit.models import Action
    from audit.services import record_from_request

    was_step_up = bool(request.session.pop(STEP_UP_FLAG_KEY, False))
    if was_step_up:
        request.session[STEP_UP_AGE_KEY] = time.time()
        try:
            request.session.modified = True
        except AttributeError:
            # plain dict in tests — `modified` only exists on a real SessionStore
            pass
    record_from_request(
        request,
        action=Action.AUTH_STEP_UP_COMPLETED if was_step_up else Action.AUTH_LOGIN,
        actor=user,
    )


def step_up_age_query(now: float | None = None) -> str:
    """Helper for templates: query string to force a step-up re-prompt."""
    return urlencode({"step_up": "1", "ts": int(now or time.time())})
