"""Test settings.

Defaults to SQLite for fast local iteration. Set ``TEST_DATABASE_URL`` to
a Postgres URL in CI to exercise the append-only triggers and JSON
queries against the production target.
"""

import os

# Force SQLite by default. CI overrides via TEST_DATABASE_URL.
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", "sqlite:///./test_advisoryhub.sqlite3"
)
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "True")
os.environ.setdefault("OIDC_RP_CLIENT_ID", "test-client")
os.environ.setdefault("OIDC_RP_CLIENT_SECRET", "test-secret")
os.environ.setdefault("OIDC_OP_AUTHORIZATION_ENDPOINT", "https://oidc.test/auth")
os.environ.setdefault("OIDC_OP_TOKEN_ENDPOINT", "https://oidc.test/token")
os.environ.setdefault("OIDC_OP_USER_ENDPOINT", "https://oidc.test/userinfo")
os.environ.setdefault("OIDC_OP_JWKS_ENDPOINT", "https://oidc.test/jwks")
os.environ.setdefault("DJANGO_SECRET_KEY", "test-secret-key")

from .base import *  # noqa: E402, F401, F403

DEBUG = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
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
