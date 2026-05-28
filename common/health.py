"""Liveness and readiness endpoints.

* ``/healthz`` — does the Django process answer? Returns 200 always.
  Use this for liveness probes.
* ``/readyz`` — *and* are our dependencies reachable? Pings the default
  database, the cache, and (when configured) the publication Git remote.
  Returns 200 only if every check passes; otherwise 503 with a JSON
  payload listing the failed checks.

Neither endpoint touches the audit log or other workflow state — they
are deliberately cheap so a noisy probe never causes load.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET

log = logging.getLogger(__name__)


@csrf_exempt
@require_GET
def healthz(_request):
    """Cheap liveness check — process up."""
    return JsonResponse({"status": "ok"})


@csrf_exempt
@require_GET
def readyz(_request):
    """Readiness — DB, cache, and (optional) git remote reachable."""
    failures: dict[str, str] = {}
    _check("db", _check_db, failures)
    _check("cache", _check_cache, failures)
    if getattr(settings, "PUB_REPO_URL", "") and getattr(
        settings, "READYZ_INCLUDE_PUB_REPO", False
    ):
        _check("publication_repo", _check_pub_repo, failures)

    if failures:
        return JsonResponse({"status": "fail", "failures": failures}, status=503)
    return JsonResponse({"status": "ok"})


def _check(name: str, fn: Callable[[], None], failures: dict) -> None:
    try:
        fn()
    except Exception as exc:  # log full trace, return short message to caller
        log.warning("readyz check %s failed: %s", name, exc, exc_info=True)
        failures[name] = type(exc).__name__


def _check_db() -> None:
    with connection.cursor() as cur:
        cur.execute("SELECT 1")
        cur.fetchone()


def _check_cache() -> None:
    cache.set("readyz", "ok", 5)
    if cache.get("readyz") != "ok":
        raise RuntimeError("cache round-trip mismatch")


def _check_pub_repo() -> None:
    """Optional: `git ls-remote` against the configured publication URL.

    Off by default (READYZ_INCLUDE_PUB_REPO=False) because it's a
    network round-trip and we don't want every readiness probe to
    egress to GitHub.
    """
    import subprocess

    cmd = ["git", "ls-remote", "--exit-code", "--heads", settings.PUB_REPO_URL]
    subprocess.run(cmd, check=True, capture_output=True, timeout=5)
