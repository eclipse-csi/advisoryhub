"""Account-related signal receivers.

Registered from :meth:`accounts.apps.AccountsConfig.ready`. This module owns
sign-out auditing; sign-in / step-up auditing lives in :mod:`accounts.step_up`
(the sole ``user_logged_in`` receiver, which already reads the step-up flag so
it can tell a genuine login from a step-up re-auth).
"""

from __future__ import annotations

from django.contrib.auth.signals import user_logged_out
from django.dispatch import receiver


@receiver(user_logged_out)
def record_logout(sender, request, user, **kwargs):  # noqa: ARG001
    """Record a sign-out in the ephemeral access log.

    Fires from mozilla-django-oidc's ``OIDCLogoutView`` (which calls
    ``django.contrib.auth.logout``). ``user`` is ``None`` when logout is invoked
    on an already-anonymous request — nothing to record in that case. The audit
    import is deferred to keep app loading free of an accounts↔audit cycle,
    matching the pattern in :mod:`accounts.auth`.
    """
    if user is None or request is None:
        return
    from audit.models import Action
    from audit.services import record_from_request

    record_from_request(request, action=Action.AUTH_LOGOUT, actor=user)
