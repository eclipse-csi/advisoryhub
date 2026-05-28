"""Sentry initialization, gated on ``SENTRY_DSN``.

When the env var is empty (the default), this is a complete no-op — no
network calls, no allocations beyond the import. When set, both Django
view exceptions and Celery task exceptions are captured.

Trace sample rate defaults to 0 (errors only). Set ``SENTRY_TRACES_SAMPLE_RATE``
to 0.05–0.10 in production if you want tracing too.
"""

from __future__ import annotations


def init_from_env() -> bool:
    """Returns True iff Sentry was initialized."""
    import os

    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        return False
    try:
        import sentry_sdk
        from sentry_sdk.integrations.celery import CeleryIntegration
        from sentry_sdk.integrations.django import DjangoIntegration
    except ImportError:  # pragma: no cover — sentry-sdk is in pyproject
        return False

    sentry_sdk.init(
        dsn=dsn,
        integrations=[DjangoIntegration(), CeleryIntegration()],
        traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0")),
        send_default_pii=False,
        # Strip request bodies — advisories may contain sensitive details.
        max_request_body_size="never",
        environment=os.environ.get("SENTRY_ENVIRONMENT", "production"),
        release=os.environ.get("SENTRY_RELEASE") or None,
    )
    return True
