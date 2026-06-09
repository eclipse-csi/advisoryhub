"""Celery task metrics + a worker-local Prometheus exporter.

The worker produces the publication and per-task metrics, but it serves no HTTP —
so those series can't reach the web app's ``/metrics``. Instead the worker starts
its own Prometheus exposition endpoint (``prometheus_client.start_http_server``)
on ``PROMETHEUS_WORKER_METRICS_PORT``, which Prometheus scrapes as a separate
target. The port defaults to ``0`` (disabled), so the web process, tests, and
ad-hoc ``manage.py`` invocations never bind it; docker-compose sets it to ``9808``.

**Pool assumption — single process.** The exporter is started on ``worker_ready``,
which fires in the worker's *MainProcess*. That is correct for a single-process
pool (``--pool=threads`` — what docker-compose uses — or ``gevent``/``eventlet``/
``solo``): every task runs in that one process, so the module-global metric
objects and the exporter live together and a single endpoint sees all task
threads' counts. ``--concurrency`` can therefore be raised freely.

This is deliberately NOT wired to ``worker_process_init`` (which fires per
*forked child*): with the default **prefork** pool the children have separate
memory, so a MainProcess exporter would miss their counts and a per-child
exporter would collide on the fixed port. If you ever switch to prefork, use
``prometheus_client`` multiprocess mode (a per-container ``PROMETHEUS_MULTIPROC_DIR``
+ a single aggregating endpoint) instead — same mechanism as the gunicorn web
path (see ``gunicorn.conf.py`` / ``config/settings/prod.py``).

Signal handlers are connected at app-ready time (``audit/apps.py``); they are
inert in the web process because ``worker_ready`` only fires in a worker.

Counting policy: the outcome is derived from ``state`` in ``task_postrun``,
which fires exactly once per execution in BOTH real-worker and eager modes.
``task_failure`` is deliberately not used — it never fires under eager
(``task_always_eager``), and in a real worker both ``task_failure`` and
``task_postrun`` fire, so counting in postrun alone is exactly-once everywhere.
(Under eager, ``task_postrun`` reports ``state=None`` on failure rather than
``"FAILURE"``, so anything that is not ``SUCCESS``/``RETRY`` counts as a
failure.)
"""

from __future__ import annotations

import logging
import time

from celery.signals import task_postrun, task_prerun, worker_ready
from django.conf import settings

from common import metrics

log = logging.getLogger(__name__)

# task_id -> monotonic start time, set in prerun and consumed in postrun.
_starts: dict[str, float] = {}

# Celery state string -> the `status` label we publish. Anything not listed
# (FAILURE, None under eager, REVOKED, …) is treated as a failure.
_STATUS_FOR_STATE = {"SUCCESS": "success", "RETRY": "retry"}


def _start_exporter() -> bool:
    """Start the worker-local Prometheus exporter when a port is configured.

    Returns ``True`` when a port is set (and a bind was attempted), ``False``
    when disabled (port ``0``). An already-bound port surfaces as ``OSError``
    and is logged, not raised.
    """
    port = int(getattr(settings, "PROMETHEUS_WORKER_METRICS_PORT", 0) or 0)
    if not port:
        return False
    from prometheus_client import start_http_server

    try:
        start_http_server(port)
        log.info("worker metrics exporter listening on :%s", port)
    except OSError as exc:  # already bound (e.g. a second worker on the same host)
        log.info("worker metrics exporter not started on :%s (%s)", port, exc)
    return True


@worker_ready.connect
def _on_worker_ready(**_kwargs):
    _start_exporter()


@task_prerun.connect
def _on_task_prerun(task_id=None, **_kwargs):
    if task_id is not None:
        _starts[task_id] = time.monotonic()


@task_postrun.connect
def _on_task_postrun(task_id=None, task=None, state=None, **_kwargs):
    name = getattr(task, "name", "unknown")
    start = _starts.pop(task_id, None) if task_id is not None else None
    if start is not None:
        metrics.celery_task_duration_seconds.labels(task=name).observe(time.monotonic() - start)
    status = _STATUS_FOR_STATE.get(state or "", "failure")
    metrics.celery_task_total.labels(task=name, status=status).inc()
