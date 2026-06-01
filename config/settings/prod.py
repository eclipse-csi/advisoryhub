from .base import *  # noqa: F401, F403

DEBUG = False
SECURE_HSTS_SECONDS = 60 * 60 * 24 * 365
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True

# ---------------------------------------------------------------------------
# Static files (production) — WhiteNoise
# ---------------------------------------------------------------------------
# Serve hashed, compressed, immutable static assets straight from the app, so
# no separate static host/CDN is needed (and none of the assets are third-party).
#   - CompressedManifestStaticFilesStorage: content-hashed filenames (enabling
#     safe far-future, immutable Cache-Control) plus precompressed gzip/brotli.
#   - WhiteNoiseMiddleware runs immediately after SecurityMiddleware.
# Deploy steps: run `python manage.py collectstatic --noinput` at build/release
# time, and serve under a real WSGI/ASGI server (e.g. `gunicorn config.wsgi`),
# never the dev runserver. (The dev docker-compose keeps runserver + Django's
# static handler; this block only affects prod.)
MIDDLEWARE = list(MIDDLEWARE)  # noqa: F405
MIDDLEWARE.insert(
    MIDDLEWARE.index("django.middleware.security.SecurityMiddleware") + 1,
    "whitenoise.middleware.WhiteNoiseMiddleware",
)

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

# Hashed asset names are immutable; WhiteNoise serves them with a 1-year
# immutable Cache-Control automatically. This sets the max-age for any
# non-hashed fallbacks too.
WHITENOISE_MAX_AGE = 60 * 60 * 24 * 365
