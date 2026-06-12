"""Custom application metrics published on the Prometheus ``/metrics`` endpoint.

``django_prometheus`` already exports generic HTTP/DB/cache series. This module
adds the *business* series that answer operational questions AdvisoryHub-specific
monitoring needs: are publications succeeding, how long do they take, are Celery
tasks failing, and how deep are the operator queues.

All objects register on the default ``prometheus_client`` registry at import time
(the same registry ``django_prometheus`` serves), so importing this module
anywhere — a view, a task, or a Celery signal handler — wires the series in once.

Process topology (see docs/specification/architecture.md §8.3): the web process
serves ``/metrics`` but the publication/Celery series are produced in the *worker*
process, which exposes its own exporter (``common.celery_metrics``) on a separate
scrape target. The backlog gauge is refreshed by a beat task that runs in the
worker, so those series land on the worker target too.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# ---------------------------------------------------------------------------
# Publication pipeline (incremented in publication/services.py + tasks.py)
# ---------------------------------------------------------------------------
publication_total = Counter(
    "advisoryhub_publication_total",
    "Publication runs by lifecycle status.",
    # started | succeeded | failed. 'failed' includes rows flipped by the
    # stale-task reaper (services.reap_stale_tasks, INV-PUB-7); a queued-reap
    # increments 'failed' with no matching 'started' — deliberate skew.
    ["status"],
)

publication_stage_total = Counter(
    "advisoryhub_publication_stage_total",
    "Publication pipeline stage completions.",
    # osv_generated | csaf_generated | cve_generated | git_commit | git_push |
    # git_push_failed
    ["stage"],
)

publication_duration_seconds = Histogram(
    "advisoryhub_publication_duration_seconds",
    "Wall-clock duration of a publication run, from mark_running to a terminal state.",
    buckets=(1, 2.5, 5, 10, 30, 60, 120, 300, 600),
)

# ---------------------------------------------------------------------------
# LLM-assisted duplicate detection (incremented in similarity/services.py).
# Per-run duration is covered by the generic celery_task_duration_seconds
# series below (task="similarity.run_similarity_check").
# ---------------------------------------------------------------------------
similarity_check_total = Counter(
    "advisoryhub_similarity_check_total",
    "Similarity (duplicate-detection) checks by lifecycle status.",
    ["status"],  # started | succeeded | failed
)

# ---------------------------------------------------------------------------
# Celery tasks (set from signal handlers in common/celery_metrics.py)
# ---------------------------------------------------------------------------
celery_task_total = Counter(
    "advisoryhub_celery_task_total",
    "Celery task executions by task name and outcome.",
    ["task", "status"],  # success | failure | retry
)

celery_task_duration_seconds = Histogram(
    "advisoryhub_celery_task_duration_seconds",
    "Celery task runtime from prerun to postrun.",
    ["task"],
    buckets=(0.05, 0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 300, 600),
)

# ---------------------------------------------------------------------------
# Operator backlog (refreshed periodically from the DB by a beat task)
# ---------------------------------------------------------------------------
# multiprocess_mode="mostrecent" is load-bearing under gunicorn: without it the
# served value is the SUM of every worker's last-written value instead of the
# latest one. It is ignored (harmless) when PROMETHEUS_MULTIPROC_DIR is unset,
# e.g. in dev/test and the single-process worker.
backlog = Gauge(
    "advisoryhub_backlog",
    "Open operator work items by queue, refreshed periodically from the database.",
    # pub_failed | cve_open | review_open | triage | triage_routing | orphan |
    # reassignment
    ["queue"],
    multiprocess_mode="mostrecent",
)
