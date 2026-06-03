"""Celery wrappers around :mod:`projects.services`.

Thin by design — all logic lives in the services module so it's directly
callable from the management command and from tests without a worker.
"""

from __future__ import annotations

import logging

from celery import shared_task
from django.conf import settings

logger = logging.getLogger(__name__)


@shared_task(name="projects.tasks.run_roster_sync")
def run_roster_sync() -> dict:
    """Periodic beat task: refresh every project's security-team roster.

    Gated by ``PMI_ROSTER_SYNC_ENABLED`` (default off) so the feature stays
    dormant until Eclipse API credentials are configured. Per-project failures
    are recorded inline and never raise — one Eclipse API 5xx must not stop the
    next scheduled run from firing.
    """
    if not getattr(settings, "PMI_ROSTER_SYNC_ENABLED", False):
        return {"skipped": "PMI_ROSTER_SYNC_ENABLED is False"}
    from . import services

    return services.sync_all_security_team_rosters(by=None)
