"""Broker-safe Celery task enqueueing.

Wraps ``task.delay(...)`` so a transient broker outage (Valkey/Redis down)
never turns the user's request into a 500. By the time anything is
enqueued the DB state is already committed (callers use
``transaction.on_commit``), and every consumer re-reads state at run time,
so silently dropping the enqueue is safe: an operator re-triggers the work
from the dashboard once the broker is back.

Before this helper the same try/except was hand-rolled in ~8 places with
inconsistent coverage — some sites swallowed broker errors, others let
them escape (notably the public intake submission). Funnel new enqueue
sites through here.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def safe_enqueue(task, *args, **kwargs) -> None:
    """Enqueue ``task`` via ``.delay`` and never raise on a broker outage."""
    try:
        task.delay(*args, **kwargs)
    except Exception:
        # Broker offline shouldn't break the request that triggered it.
        log.warning("broker offline; skipped enqueue of %s", getattr(task, "name", task))
