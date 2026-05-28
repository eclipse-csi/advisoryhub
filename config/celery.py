"""Celery application entry point.

Run a worker with::

    celery -A config worker -l info

The broker is Valkey (Redis-compatible); the configured `redis://` URL works
unchanged against a Valkey server.
"""

from __future__ import annotations

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

app = Celery("advisoryhub")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
