"""Test settings.

Runs against PostgreSQL — the same engine as prod, dev, and demo — so the
append-only audit triggers, the advisory no-delete trigger, the ``pg_trgm``
indexes, and JSONB queries are all exercised. Defaults to the local
compose Postgres; set ``TEST_DATABASE_URL`` to point at a different
host/port (CI sets it to its service container).
"""

import os

# Default to the local compose Postgres; override host/port via TEST_DATABASE_URL.
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", "postgres://advisoryhub:advisoryhub@localhost:5432/advisoryhub"
)
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "True")
os.environ.setdefault("OIDC_RP_CLIENT_ID", "test-client")
os.environ.setdefault("OIDC_RP_CLIENT_SECRET", "test-secret")
os.environ.setdefault("OIDC_OP_AUTHORIZATION_ENDPOINT", "https://oidc.test/auth")
os.environ.setdefault("OIDC_OP_TOKEN_ENDPOINT", "https://oidc.test/token")
os.environ.setdefault("OIDC_OP_USER_ENDPOINT", "https://oidc.test/userinfo")
os.environ.setdefault("OIDC_OP_JWKS_ENDPOINT", "https://oidc.test/jwks")
os.environ.setdefault("DJANGO_SECRET_KEY", "test-secret-key")

from .base import *  # noqa: F403

DEBUG = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
# __Host- requires HTTPS; tests run over HTTP, so use the unprefixed names.
SESSION_COOKIE_NAME = "sessionid"
CSRF_COOKIE_NAME = "csrftoken"
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# Drop OIDC's SessionRefresh in tests — force_login doesn't establish an
# OIDC session, and the middleware would otherwise redirect every request
# to the IdP. The behavior is exercised in production via real OIDC flows.
MIDDLEWARE = [m for m in MIDDLEWARE if "mozilla_django_oidc" not in m]  # noqa: F405

# Rate limits would otherwise pollute most tests; the dedicated
# ratelimit_* tests re-enable them via @override_settings.
RATELIMIT_ENABLE = False

# Step-up auth would otherwise redirect every publish click in tests
# through the OIDC flow; the dedicated step-up tests re-enable it.
STEP_UP_REQUIRED = False

# Auto-publish would otherwise fire a publication pipeline on every webhook/sync
# of a GitHub-published GHSA-linked advisory; the dedicated auto-publish tests
# re-enable it via @override_settings.
GHSA_AUTO_PUBLISH_ENABLED = False

# Never bind the worker metrics exporter in tests (it's 0 by default too, but
# pin it so a stray env var can't make worker_process_init try to open a port).
PROMETHEUS_WORKER_METRICS_PORT = 0
