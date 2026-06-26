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


# --- Row-level-security principal for tasks (INV-CONF-2) --------------------
# Every task runs as a trusted *system* principal: it re-checks authorization
# and recipient lists in application code (INV-AUTH-1 / INV-PRIVACY-2), and RLS
# backstops the user-facing request path, not background work. No-op effect
# under a superuser DB role (dev/CI); load-bearing under the production
# non-superuser app role, where an unset principal would otherwise fail closed
# and the worker would see no rows. See common.rls.
from celery.signals import task_postrun, task_prerun  # noqa: E402


@task_prerun.connect
def _rls_set_system_principal(**kwargs):
    from common.rls import set_principal

    set_principal(user_id=None, is_admin=True)


@task_postrun.connect
def _rls_clear_principal(**kwargs):
    from common.rls import clear_principal

    clear_principal()
