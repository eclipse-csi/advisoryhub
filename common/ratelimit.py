"""Rate-limit helpers for AdvisoryHub.

Built on django-ratelimit. Each writeable endpoint that we expose to
end-users gets a per-user quota with an IP backstop. The ``per_user_or_ip``
key uses the authenticated user when present (so a logged-in user has a
predictable budget across IPs) and falls back to the source IP for the
rare unauthenticated request.

Two decorators are provided:

* ``html_ratelimit`` — for HTML/HTMX views. On hit, returns a 429
  response with a tiny human message.
* ``json_ratelimit`` — for JSON API views. On hit, returns the
  ``{error: "rate_limited", message}`` body.

Both take exactly one ``rate`` argument (e.g. ``"30/m"``) and optionally
a ``key`` override.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps

from django.http import HttpResponse
from django_ratelimit.core import is_ratelimited

from common.net import client_ip_key


def per_user_or_ip(group, request) -> str:
    """Authenticated user pk if present, else client IP."""
    if request.user.is_authenticated:
        return f"u:{request.user.pk}"
    return client_ip_key(group, request)


def _check_limited(view, request, *, rate, key) -> bool:
    """Evaluate (and count) the limit *before* the view runs.

    ``increment=True`` mirrors what ``ratelimit(block=False)`` did internally;
    passing the same ``group``/``key``/``rate`` (``method`` defaults to ``ALL``
    in both) keeps the cache key — and therefore the counting semantics —
    identical. The only change vs. the old wrapper is ordering: the caller
    short-circuits with a 429 instead of running the view (INV-RATELIMIT-1).
    """
    limited = is_ratelimited(
        request=request,
        group=view.__qualname__,
        key=key,
        rate=rate,
        increment=True,
    )
    # Preserve the django-ratelimit contract for any middleware that reads it.
    request.limited = limited or getattr(request, "limited", False)
    return limited


def html_ratelimit(*, rate: str, key: Callable | str = per_user_or_ip) -> Callable:
    def deco(view):
        @wraps(view)
        def inner(request, *args, **kwargs):
            if _check_limited(view, request, rate=rate, key=key):
                return HttpResponse(
                    "Rate limit exceeded. Try again in a minute.",
                    status=429,
                    content_type="text/plain",
                )
            return view(request, *args, **kwargs)

        return inner

    return deco


def json_ratelimit(*, rate: str, key: Callable | str = per_user_or_ip) -> Callable:
    from api.responses import error  # local to keep api → common edge clean

    def deco(view):
        @wraps(view)
        def inner(request, *args, **kwargs):
            if _check_limited(view, request, rate=rate, key=key):
                return error(
                    "rate_limited",
                    "Rate limit exceeded; please retry shortly.",
                    status=429,
                )
            return view(request, *args, **kwargs)

        return inner

    return deco
