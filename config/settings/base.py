"""Base settings for AdvisoryHub.

All environment-driven configuration lives here. Environment-specific overrides
go in dev.py, prod.py, test.py.
"""

from __future__ import annotations

from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent.parent

env = environ.Env(
    DJANGO_DEBUG=(bool, False),
    DJANGO_ALLOWED_HOSTS=(list, ["*"]),
    DJANGO_SECRET_KEY=(str, "insecure-change-me"),
    DJANGO_TIME_ZONE=(str, "UTC"),
    # Database
    DATABASE_URL=(str, "postgres://advisoryhub:advisoryhub@localhost:5432/advisoryhub"),
    # OIDC
    OIDC_RP_CLIENT_ID=(str, ""),
    OIDC_RP_CLIENT_SECRET=(str, ""),
    OIDC_OP_AUTHORIZATION_ENDPOINT=(str, ""),
    OIDC_OP_TOKEN_ENDPOINT=(str, ""),
    OIDC_OP_USER_ENDPOINT=(str, ""),
    OIDC_OP_JWKS_ENDPOINT=(str, ""),
    OIDC_OP_LOGOUT_ENDPOINT=(str, ""),
    OIDC_RP_SIGN_ALGO=(str, "RS256"),
    OIDC_VERIFY_SSL=(bool, True),
    OIDC_GROUP_CLAIM=(str, "groups"),
    OIDC_ADMIN_GROUP=(str, "advisoryhub-security"),
    # Celery / Valkey
    CELERY_BROKER_URL=(str, "redis://localhost:6379/0"),
    CELERY_RESULT_BACKEND=(str, "redis://localhost:6379/1"),
    CELERY_TASK_ALWAYS_EAGER=(bool, False),
    # Email
    EMAIL_BACKEND=(str, "django.core.mail.backends.console.EmailBackend"),
    DEFAULT_FROM_EMAIL=(str, "AdvisoryHub <noreply@example.org>"),
    # Publication Git repository
    PUB_REPO_URL=(str, ""),
    PUB_REPO_BRANCH=(str, "main"),
    PUB_REPO_AUTH=(str, "ssh"),  # ssh|token
    PUB_REPO_SSH_KEY_PATH=(str, ""),
    PUB_REPO_TOKEN=(str, ""),
    PUB_COMMIT_AUTHOR_NAME=(str, "AdvisoryHub Bot"),
    PUB_COMMIT_AUTHOR_EMAIL=(str, "advisoryhub-bot@example.org"),
    # OSV/CSAF files are bucketed by the advisory's publication year.
    # Placeholders: {advisory_id}, {year} (the year of first publication).
    PUB_OSV_PATH_TEMPLATE=(str, "osv/{year}/{advisory_id}.json"),
    PUB_CSAF_PATH_TEMPLATE=(str, "csaf/{year}/{advisory_id}.json"),
    # CVE Record export (only for advisories with an EF-assigned CVE).
    # Default path mirrors the official CVEProject/cvelistV5 layout:
    # ``cves/<year>/<thousands>xxx/<CVE-id>.json``.
    PUB_CVE_PATH_TEMPLATE=(str, "cves/{year}/{bucket}/{cve_id}.json"),
    # Eclipse Foundation CNA identity, written into the CVE record's
    # ``assignerOrgId``/``providerMetadata.orgId``. The org id is a v4 UUID
    # and MUST be set in prod — publishing a CVE-assigned advisory fails
    # loudly while it is empty (see publication.cve.CveAssignerNotConfigured).
    PUB_CVE_ASSIGNER_ORG_ID=(str, ""),
    PUB_CVE_ASSIGNER_SHORT_NAME=(str, "eclipse"),
    # GitHub App (GHSA integration). Installations are stored in the
    # ``ghsa_githubappinstallation`` table — there is no env-var
    # short-circuit. Run ``manage.py discover_github_installations`` (or
    # wait for the first ``installation.created`` webhook) to populate it.
    GHSA_FEATURE_ENABLED=(bool, False),
    GITHUB_APP_ID=(int, 0),
    GITHUB_APP_PRIVATE_KEY_PATH=(str, ""),  # preferred in prod
    GITHUB_APP_PRIVATE_KEY=(str, ""),  # inline fallback for dev
    GITHUB_APP_WEBHOOK_SECRET=(str, ""),  # SECRET — HMAC key for inbound webhooks
    GITHUB_APP_API_BASE_URL=(str, "https://api.github.com"),
    # Eclipse Foundation PMI API (source-of-truth for project↔repo)
    PMI_API_BASE_URL=(str, "https://projects.eclipse.org/api"),
    PMI_API_TOKEN=(str, ""),  # blank by default; PMI is public
    PMI_SYNC_INTERVAL_HOURS=(int, 6),
    # Public vulnerability report intake. hCaptcha keys default to empty;
    # the form silently bypasses captcha verification when either is unset
    # (natural dev/test mode).
    HCAPTCHA_SITE_KEY=(str, ""),
    HCAPTCHA_SECRET_KEY=(str, ""),
    RATELIMIT_INTAKE_ANON=(str, "5/h"),
    RATELIMIT_INTAKE_USER=(str, "20/h"),
    INTAKE_REPORT_RETENTION_DAYS=(int, 365),
    INTAKE_DISABLED=(bool, False),
    # Number of trusted reverse proxies that append to X-Forwarded-For
    # directly in front of the app. 0 = ignore XFF and use REMOTE_ADDR.
    # See common.net.client_ip. Set to the real proxy depth in prod (e.g.
    # 1 behind a single ingress/LB) so per-IP rate limits and audit IPs
    # reflect the true client and can't be spoofed via a forged header.
    TRUSTED_PROXY_COUNT=(int, 0),
)

# Read .env if present (silently ignored if missing)
env_file = BASE_DIR / ".env"
if env_file.exists():
    environ.Env.read_env(str(env_file))

# ---------------------------------------------------------------------------
# Core Django
# ---------------------------------------------------------------------------
SECRET_KEY = env("DJANGO_SECRET_KEY")
DEBUG = env("DJANGO_DEBUG")
ALLOWED_HOSTS = env("DJANGO_ALLOWED_HOSTS")
TIME_ZONE = env("DJANGO_TIME_ZONE")
USE_TZ = True
USE_I18N = True
LANGUAGE_CODE = "en-us"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.User"

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "django_htmx",
    "mozilla_django_oidc",
    "django_prometheus",
    # Project apps
    "accounts",
    "projects",
    "audit",
    "advisories",
    "access",
    "comments",
    "notifications",
    "workflows",
    "publication",
    "admin_console",
    "api",
    "ghsa",
    "intake",
]

MIDDLEWARE = [
    # PrometheusBeforeMiddleware MUST be the first entry so its timer
    # captures the entire request lifetime; PrometheusAfterMiddleware
    # MUST be last so it sees the final response.
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    "common.middleware.RequestIDMiddleware",
    "django.middleware.security.SecurityMiddleware",
    # CSP nonce must be available during template render and the header set on
    # every response — keep high in the stack, just after SecurityMiddleware.
    "csp.middleware.CSPMiddleware",
    "common.middleware.PermissionsPolicyMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    # LocaleMiddleware must come *after* SessionMiddleware (so it can
    # consult the session's preferred language) and *before*
    # CommonMiddleware (Django docs).
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "mozilla_django_oidc.middleware.SessionRefresh",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django_htmx.middleware.HtmxMiddleware",
    # After auth (needs request.user) and htmx (needs request.htmx) so the
    # maintenance gate can identify admins and answer HTMX writes cleanly.
    "common.middleware.MaintenanceModeMiddleware",
    "django_prometheus.middleware.PrometheusAfterMiddleware",
]

# ---------------------------------------------------------------------------
# i18n
# ---------------------------------------------------------------------------
LANGUAGES = [
    ("en", "English"),
    ("fr", "Français"),
]
LOCALE_PATHS = [BASE_DIR / "locale"]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "common.context_processors.maintenance_mode",
            ],
        },
    }
]

DATABASES = {"default": env.db_url("DATABASE_URL")}

# ---------------------------------------------------------------------------
# Cache (used by django-ratelimit and any future view caching)
# ---------------------------------------------------------------------------
# Default to a process-local LocMem cache; production should override by
# setting CACHE_URL to the same Valkey/Redis instance Celery uses, e.g.
# CACHE_URL=redis://valkey:6379/2.
_CACHE_URL = env.str("CACHE_URL", default="")
if _CACHE_URL:
    CACHES = {"default": env.cache_url("CACHE_URL")}
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "advisoryhub-default",
        }
    }

# Rate-limit master switch — toggle to False in tests / local debugging.
RATELIMIT_ENABLE = env.bool("RATELIMIT_ENABLE", default=True)

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

# ---------------------------------------------------------------------------
# Authentication / OIDC
# ---------------------------------------------------------------------------
AUTHENTICATION_BACKENDS = [
    "accounts.auth.AdvisoryHubOIDCBackend",
    "django.contrib.auth.backends.ModelBackend",
]

LOGIN_URL = "/oidc/authenticate/"
LOGIN_REDIRECT_URL = "/advisories/"
# Anonymous landing page so the post-logout redirect doesn't bounce the user
# through OIDC again (which would silently re-authenticate them via the OP's
# SSO session and make "Sign out" appear to be a no-op).
LOGOUT_REDIRECT_URL = "/accounts/signed-out/"

OIDC_RP_CLIENT_ID = env("OIDC_RP_CLIENT_ID")
OIDC_RP_CLIENT_SECRET = env("OIDC_RP_CLIENT_SECRET")
OIDC_OP_AUTHORIZATION_ENDPOINT = env("OIDC_OP_AUTHORIZATION_ENDPOINT")
OIDC_OP_TOKEN_ENDPOINT = env("OIDC_OP_TOKEN_ENDPOINT")
OIDC_OP_USER_ENDPOINT = env("OIDC_OP_USER_ENDPOINT")
OIDC_OP_JWKS_ENDPOINT = env("OIDC_OP_JWKS_ENDPOINT")
# RP-initiated logout (OIDC end_session_endpoint). When set, "Sign out" also
# terminates the OP-side SSO session via accounts.auth.provider_logout.
OIDC_OP_LOGOUT_ENDPOINT = env("OIDC_OP_LOGOUT_ENDPOINT")
OIDC_OP_LOGOUT_URL_METHOD = "accounts.auth.provider_logout"
# Required so provider_logout can pass id_token_hint to the OP end-session
# endpoint (most OPs reject RP-initiated logout without it).
OIDC_STORE_ID_TOKEN = True
OIDC_RP_SIGN_ALGO = env("OIDC_RP_SIGN_ALGO")
OIDC_RP_SCOPES = "openid email profile groups"
# Kanidm enforces PKCE on confidential OAuth2 clients by default
# (good!), and most modern IdPs do the same. mozilla-django-oidc has
# PKCE support but it's opt-in.
OIDC_USE_PKCE = env.bool("OIDC_USE_PKCE", default=True)
OIDC_PKCE_CODE_CHALLENGE_METHOD = "S256"
# When the OIDC OP uses a self-signed cert (the dev kanidm bundle) flip
# this to False via the env. Defaults to True for production safety.
OIDC_VERIFY_SSL = env("OIDC_VERIFY_SSL")

# ---------------------------------------------------------------------------
# Step-up auth (publish action). Set STEP_UP_REQUIRED=False in dev if you
# don't want to re-authenticate on every publish click; keep True in prod.
# ---------------------------------------------------------------------------
STEP_UP_REQUIRED = env.bool("STEP_UP_REQUIRED", default=True)
STEP_UP_MAX_AGE_SECONDS = env.int("STEP_UP_MAX_AGE_SECONDS", default=300)

# AdvisoryHub-specific OIDC config. Note: "mature publisher" status is
# stored on the Project row (Project.is_mature_publisher), not derived
# from OIDC group membership — it's an editorial decision per project.
OIDC_GROUP_CLAIM = env("OIDC_GROUP_CLAIM")
OIDC_ADMIN_GROUP = env("OIDC_ADMIN_GROUP")

# ---------------------------------------------------------------------------
# Celery / Valkey
# ---------------------------------------------------------------------------
CELERY_BROKER_URL = env("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND")
CELERY_TASK_ALWAYS_EAGER = env("CELERY_TASK_ALWAYS_EAGER")
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
EMAIL_BACKEND = env("EMAIL_BACKEND")
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL")

# ---------------------------------------------------------------------------
# Publication Git repository
# ---------------------------------------------------------------------------
PUB_REPO_URL = env("PUB_REPO_URL")
PUB_REPO_BRANCH = env("PUB_REPO_BRANCH")
PUB_REPO_AUTH = env("PUB_REPO_AUTH")
PUB_REPO_SSH_KEY_PATH = env("PUB_REPO_SSH_KEY_PATH")
PUB_REPO_TOKEN = env("PUB_REPO_TOKEN")
PUB_COMMIT_AUTHOR_NAME = env("PUB_COMMIT_AUTHOR_NAME")
PUB_COMMIT_AUTHOR_EMAIL = env("PUB_COMMIT_AUTHOR_EMAIL")
PUB_OSV_PATH_TEMPLATE = env("PUB_OSV_PATH_TEMPLATE")
PUB_CSAF_PATH_TEMPLATE = env("PUB_CSAF_PATH_TEMPLATE")
PUB_CVE_PATH_TEMPLATE = env("PUB_CVE_PATH_TEMPLATE")
PUB_CVE_ASSIGNER_ORG_ID = env("PUB_CVE_ASSIGNER_ORG_ID")
PUB_CVE_ASSIGNER_SHORT_NAME = env("PUB_CVE_ASSIGNER_SHORT_NAME")

# ---------------------------------------------------------------------------
# GHSA integration (GitHub App + Eclipse PMI)
#
# AdvisoryHub authenticates to GitHub as a registered GitHub App. The App
# needs only ``repository_security_advisories: read & write`` (plus the
# default ``metadata: read``) and is installed per-repo by Eclipse org
# admins. The private key is the single load-bearing secret here — it is
# never persisted to the DB, never logged, and is rewritten by the audit
# redactor if it ever surfaces in an error message. Prefer
# GITHUB_APP_PRIVATE_KEY_PATH (file on disk, e.g. /run/secrets/...) over
# GITHUB_APP_PRIVATE_KEY (inline). v1 is single-installation; the
# installation id is configured here too.
# ---------------------------------------------------------------------------
GHSA_FEATURE_ENABLED = env("GHSA_FEATURE_ENABLED")
GITHUB_APP_ID = env("GITHUB_APP_ID")
GITHUB_APP_PRIVATE_KEY_PATH = env("GITHUB_APP_PRIVATE_KEY_PATH")
GITHUB_APP_PRIVATE_KEY = env("GITHUB_APP_PRIVATE_KEY")
GITHUB_APP_WEBHOOK_SECRET = env("GITHUB_APP_WEBHOOK_SECRET")
GITHUB_APP_API_BASE_URL = env("GITHUB_APP_API_BASE_URL")
PMI_API_BASE_URL = env("PMI_API_BASE_URL")
PMI_API_TOKEN = env("PMI_API_TOKEN")
PMI_SYNC_INTERVAL_HOURS = env("PMI_SYNC_INTERVAL_HOURS")

# Public vulnerability report intake
HCAPTCHA_SITE_KEY = env("HCAPTCHA_SITE_KEY")
HCAPTCHA_SECRET_KEY = env("HCAPTCHA_SECRET_KEY")
RATELIMIT_INTAKE_ANON = env("RATELIMIT_INTAKE_ANON")
RATELIMIT_INTAKE_USER = env("RATELIMIT_INTAKE_USER")
INTAKE_REPORT_RETENTION_DAYS = env("INTAKE_REPORT_RETENTION_DAYS")
INTAKE_DISABLED = env("INTAKE_DISABLED")

# Celery beat schedule. The worker that runs `celery -A config beat` will
# fire run_pmi_repo_sync every PMI_SYNC_INTERVAL_HOURS hours, refreshing
# the local ProjectGitHubRepository mirror from PMI. GHSA *discovery* (i.e.
# auto-creating GHSA-linked advisories) happens via explicit user-triggered
# sync, not from beat — see ghsa.tasks for the on-demand variants.
from datetime import timedelta  # noqa: E402

CELERY_BEAT_SCHEDULE = {
    "pmi-repo-mirror": {
        "task": "ghsa.tasks.run_pmi_repo_sync",
        "schedule": timedelta(hours=PMI_SYNC_INTERVAL_HOURS),
    },
}

# ---------------------------------------------------------------------------
# Security defaults
# ---------------------------------------------------------------------------
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
# Referrer-Policy ("same-origin") and Cross-Origin-Opener-Policy ("same-origin")
# are emitted by Django's SecurityMiddleware defaults; no override needed.
# (SECURE_BROWSER_XSS_FILTER was removed in Django 5.1 — the legacy
# X-XSS-Protection header is deprecated; the CSP below is the real defense.)

# ---------------------------------------------------------------------------
# Content-Security-Policy (django-csp)
# ---------------------------------------------------------------------------
# Nonce-based script-src + 'strict-dynamic': only per-request-nonced <script>
# tags (and scripts they load) execute, so an injected inline <script> or event
# handler cannot run. This is the defence-in-depth layer behind the bleach
# sanitiser that scrubs user-supplied markdown (comments/services.render_markdown).
# All scripts, styles and fonts are same-origin; inline event handlers and the
# per-form CSRF hx-headers were removed (see static/advisoryhub-dialogs.js and
# static/advisoryhub-htmx.js) so the policy needs no 'unsafe-inline'/'unsafe-hashes'.
#
# Shipped Report-Only first (CSP_REPORT_ONLY=True default) so anything missed is
# reported, not broken; set CSP_REPORT_ONLY=False to enforce once reports are clean.
from csp.constants import NONCE, NONE, REPORT_SAMPLE, SELF, STRICT_DYNAMIC  # noqa: E402

CSP_REPORT_ONLY = env.bool("CSP_REPORT_ONLY", default=True)
_CSP_REPORT_URI = env.str("CSP_REPORT_URI", default="")

_CSP_DIRECTIVES: dict = {
    "default-src": [SELF],
    "script-src": [SELF, NONCE, STRICT_DYNAMIC, REPORT_SAMPLE],
    "style-src": [SELF],
    "img-src": [SELF, "data:"],
    "font-src": [SELF],
    "connect-src": [SELF],
    "form-action": [SELF],
    "base-uri": [NONE],
    "object-src": [NONE],
    "frame-ancestors": [NONE],
}
if _CSP_REPORT_URI:
    _CSP_DIRECTIVES["report-uri"] = [_CSP_REPORT_URI]

if CSP_REPORT_ONLY:
    CONTENT_SECURITY_POLICY_REPORT_ONLY = {"DIRECTIVES": _CSP_DIRECTIVES}
else:
    CONTENT_SECURITY_POLICY = {"DIRECTIVES": _CSP_DIRECTIVES}

# Source-IP resolution (see common.net.client_ip). 0 = trust only the
# direct peer (REMOTE_ADDR); raise to the number of trusted proxies that
# append to X-Forwarded-For in front of the app.
TRUSTED_PROXY_COUNT = env("TRUSTED_PROXY_COUNT")

# ---------------------------------------------------------------------------
# Logging — single-line JSON to stderr, with the current request id on
# every record so a log shipper can stitch a request together.
# ---------------------------------------------------------------------------
LOG_FORMAT = env.str("LOG_FORMAT", default="json")  # "json" | "plain"
LOG_LEVEL = env.str("LOG_LEVEL", default="INFO")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "request_id": {"()": "common.logging.RequestIDFilter"},
    },
    "formatters": {
        "json": {"()": "common.logging.JSONFormatter"},
        "plain": {
            "format": "[%(asctime)s] %(levelname)s %(name)s req=%(request_id)s :: %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "filters": ["request_id"],
            "formatter": LOG_FORMAT,
        },
    },
    "root": {"handlers": ["console"], "level": LOG_LEVEL},
    "loggers": {
        "django.request": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "django.server": {"handlers": ["console"], "level": "WARNING", "propagate": False},
    },
}

# ---------------------------------------------------------------------------
# Sentry — initialized only if SENTRY_DSN is set in the environment.
# ---------------------------------------------------------------------------
from common.sentry import init_from_env as _init_sentry  # noqa: E402

_init_sentry()
