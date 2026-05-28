"""Network helpers shared across apps.

Single home for request source-IP extraction so rate-limit keys, audit
entries, and intake fingerprints all agree on what "the client IP" is.
"""

from __future__ import annotations

from django.conf import settings


def client_ip(request) -> str | None:
    """Source IP for ``request``, honouring the trusted-proxy depth.

    ``settings.TRUSTED_PROXY_COUNT`` is the number of reverse proxies that
    append to ``X-Forwarded-For`` directly in front of the app:

    * ``0`` (default): ``X-Forwarded-For`` is ignored entirely and
      ``REMOTE_ADDR`` is used. Safe by default — a client-supplied XFF can
      never spoof the source IP. Correct when the app is reached directly.
    * ``N > 0``: the client IP is the ``N``-th entry counted from the
      *right* of the XFF list — i.e. the address the outermost trusted
      proxy observed. Everything to the left of that is client-supplied
      and untrusted, so it can no longer be used to forge a source IP.

    If the header is missing or shorter than the trusted chain (tampering,
    or a proxy that didn't append), we fall back to ``REMOTE_ADDR`` rather
    than trust an attacker-controlled left-most entry.
    """
    remote_addr = request.META.get("REMOTE_ADDR")
    proxy_count = getattr(settings, "TRUSTED_PROXY_COUNT", 0)
    if proxy_count <= 0:
        return remote_addr
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if not forwarded:
        return remote_addr
    parts = [p.strip() for p in forwarded.split(",") if p.strip()]
    if len(parts) < proxy_count:
        return remote_addr
    return parts[-proxy_count]


def client_ip_key(group, request) -> str:
    """django-ratelimit ``key`` callable: buckets by ``ip:<client-ip>``."""
    return f"ip:{client_ip(request) or '?'}"
