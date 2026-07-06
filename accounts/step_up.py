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
   records the timestamp and clears the pending flag; the callback view's
   ``success_url`` then returns the user to ``next`` (the page that
   required step-up).

Why a session-scoped timestamp and not ``user.last_login``: a normal
sign-in updates ``last_login``, so basing step-up on it would let a
2-hour-old session pass the freshness check.

The freshness stamp is written *only* when two conditions hold together:
the ``step_up_pending`` flag was set (so an *intended* step-up flow is in
progress) **and** the OIDC login that just completed actually re-prompted
for credentials. The latter is proven from the ID token's ``auth_time``
claim, not from the pending flag alone — the flag is set in the session
*before* the IdP round-trip, so on its own it would also be satisfied by
an ordinary ``/oidc/authenticate/`` SSO login that never asked for
credentials. ``prompt=login&max_age=0`` makes a conformant OP set
``auth_time`` to "now" (OpenID Connect Core §3.1.2.1); a login answered
from the OP's existing SSO session carries an *old* ``auth_time``. Binding
to the claim closes the SSO carry-over bypass (see F001).
"""

from __future__ import annotations

import logging
import time

import jwt
from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.http import HttpResponseRedirect
from django.urls import reverse
from mozilla_django_oidc.views import OIDCAuthenticationRequestView

log = logging.getLogger(__name__)

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


def step_up_callback_redirect(request) -> str | None:
    """The local path to return to after a step-up flow, or ``None`` if this
    login was not one.

    ``require_step_up_or_redirect`` stashes the originating URL under
    ``STEP_UP_NEXT_KEY`` before the IdP round-trip; the OIDC callback's
    ``success_url`` (:class:`accounts.auth.AdvisoryHubOIDCCallbackView`) pops it
    here and validates it is same-host before redirecting. Returning ``None``
    rather than a default path lets an ordinary sign-in fall through to
    ``LOGIN_REDIRECT_URL``.
    """
    return request.session.pop(STEP_UP_NEXT_KEY, None)


def _login_reauthed_recently(request) -> bool:
    """Whether the OIDC login that just completed actually re-prompted for credentials.

    Decodes the freshly-issued ID token from the session (``oidc_id_token`` —
    present because ``OIDC_STORE_ID_TOKEN`` is on, and written by the backend's
    ``store_tokens`` *before* the ``user_logged_in`` signal fires) and requires
    its ``auth_time`` claim to be within ``STEP_UP_MAX_AGE_SECONDS``. The
    signature was already verified by mozilla-django-oidc at the callback before
    the token was stored, so we decode without re-verifying it.

    Fails closed: a missing token, missing/non-numeric ``auth_time``, or any
    decode error returns ``False`` — step-up is only granted on positive proof
    of a recent re-authentication. ``prompt=login&max_age=0`` makes a conformant
    OP emit a fresh ``auth_time`` (OIDC Core §3.1.2.1); if a deployment's OP
    omits it, the caller logs a warning so the misconfiguration is visible rather
    than a silent step-up failure.
    """
    id_token = request.session.get("oidc_id_token")
    if not id_token:
        return False
    try:
        claims = jwt.decode(id_token, options={"verify_signature": False})
    except Exception:  # a malformed token must never satisfy step-up
        return False
    auth_time = claims.get("auth_time")
    if not isinstance(auth_time, (int, float)) or isinstance(auth_time, bool):
        return False
    return (time.time() - auth_time) <= step_up_max_age()


@receiver(user_logged_in)
def record_step_up_on_login(sender, request, user, **kwargs):
    """When OIDC login completes, audit it and (if a real step-up flow) stamp the session.

    A step-up is recorded only when BOTH the ``step_up_pending`` flag was set
    (an *intended* step-up flow, marked by ``StepUpAuthRequestView`` or
    ``require_step_up_or_redirect`` before the redirect) AND the login that just
    completed actually re-prompted for credentials (``_login_reauthed_recently``,
    proven from the ID token's ``auth_time``). The flag alone is insufficient: it
    is set before the IdP round-trip and survives ``auth.login``'s session-key
    cycling, so an ordinary ``/oidc/authenticate/`` SSO login would otherwise
    redeem it without any credential re-entry (F001). An ordinary sign-in (no
    flag) never stamps either way. The flag is always consumed.

    This is the single ``user_logged_in`` receiver, so it also writes the
    authentication access-log entry: ``auth.step_up_completed`` for a confirmed
    step-up re-auth, ``auth.login`` otherwise (ordinary sign-in, or a pending
    flag that no re-auth backed). Reading the pending flag once here (rather than
    from a second receiver) avoids racing the ``pop``. Routed to the ephemeral
    access log via ``record_from_request`` (IP + user-agent captured); ``actor``
    is passed explicitly because ``request.user`` is not populated when the signal
    is sent manually (as in tests).
    """
    if not request:
        return
    from audit.models import Action
    from audit.services import record_from_request

    pending = bool(request.session.pop(STEP_UP_FLAG_KEY, False))
    was_step_up = pending and _login_reauthed_recently(request)
    if pending and not was_step_up:
        # An intended step-up flow that we could not confirm as a fresh re-auth.
        # Usually a non-`prompt=login` login carried the flag (the bypass we
        # refuse to honour); also fires if the OP omitted `auth_time`.
        log.warning(
            "step_up_pending was set but the login carried no fresh auth_time; "
            "not granting step-up freshness"
        )
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
