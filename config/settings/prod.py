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

# ---------------------------------------------------------------------------
# Prometheus /metrics under gunicorn (multiprocess)
# ---------------------------------------------------------------------------
# The /metrics endpoint is wired unconditionally (config/urls.py). Under
# multiple gunicorn workers the custom advisoryhub_* counters only aggregate
# correctly when prometheus_client multiprocess mode is on. The deploy MUST:
#   * set PROMETHEUS_MULTIPROC_DIR to a writable, empty-at-boot dir (tmpfs);
#   * run gunicorn with this repo's gunicorn.conf.py (its child_exit hook reaps
#     dead workers' mmap files):  gunicorn config.wsgi -c gunicorn.conf.py
# django_prometheus reads PROMETHEUS_MULTIPROC_DIR straight from the OS env, so
# there is nothing to set here — this block is the deployment checklist. The
# Celery worker exports its own series on PROMETHEUS_WORKER_METRICS_PORT (see
# common.celery_metrics); scrape both targets.
