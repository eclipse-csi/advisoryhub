"""Gunicorn config for production.

Only the Prometheus multiprocess wiring lives here; everything else stays on the
gunicorn defaults / CLI flags. Run with::

    gunicorn config.wsgi -c gunicorn.conf.py

Prometheus multiprocess mode
----------------------------
Under multiple gunicorn workers, every worker has its own process memory, so a
Counter incremented in one worker is invisible to the ``/metrics`` request that
lands on another. ``prometheus_client`` solves this by having each worker write
its samples to mmap files in ``PROMETHEUS_MULTIPROC_DIR``; ``django_prometheus``
aggregates them at scrape time when that env var is set.

For this to be correct the deployment MUST:

* set ``PROMETHEUS_MULTIPROC_DIR`` to a writable, per-replica directory (a tmpfs
  / ``emptyDir`` is ideal — it should be empty at boot), and
* call ``multiprocess.mark_process_dead`` when a worker exits, so its mmap files
  are reaped instead of double-counting forever. That is the hook below.

Without these, the custom ``advisoryhub_*`` counters still work but report only
the partial counts of whichever worker served the scrape.
"""

from __future__ import annotations


def child_exit(server, worker):
    """Reap a dead worker's Prometheus mmap files (multiprocess mode)."""
    from prometheus_client import multiprocess

    multiprocess.mark_process_dead(worker.pid)
