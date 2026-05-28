"""Celery wrappers around :mod:`ghsa.services`.

Tasks are intentionally thin — all logic lives in the services module so
it's directly callable from the management command and from tests
without spinning up a worker.
"""

from __future__ import annotations

import logging

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model

from advisories.models import Advisory

from . import services
from .models import GhsaCvePushTask, WebhookDelivery

logger = logging.getLogger(__name__)


def _resolve_user(user_id):
    if not user_id:
        return None
    try:
        return get_user_model().objects.get(pk=user_id)
    except get_user_model().DoesNotExist:
        return None


@shared_task(name="ghsa.tasks.run_pmi_repo_sync")
def run_pmi_repo_sync() -> dict:
    """Periodic beat task: refresh every Project's PMI repo mirror.

    Failures are logged at WARNING but never raise — a one-off PMI 5xx
    must not stop the next scheduled run from firing.
    """
    if not getattr(settings, "GHSA_FEATURE_ENABLED", False):
        return {"skipped": "GHSA_FEATURE_ENABLED is False"}
    from projects.models import Project

    refreshed = 0
    failed = 0
    for project in Project.objects.all():
        try:
            services.sync_project_repos_from_pmi(project, by=None)
            refreshed += 1
        except Exception:  # pragma: no cover — defensive
            failed += 1
            logger.exception("PMI repo sync raised for %s", project.slug)
    return {"refreshed": refreshed, "failed": failed}


@shared_task(name="ghsa.tasks.run_ghsa_sync_project")
def run_ghsa_sync_project(project_id, user_id=None) -> dict:
    from projects.models import Project

    project = Project.objects.get(pk=project_id)
    user = _resolve_user(user_id)
    run = services.sync_ghsas_for_project(project, by=user)
    return {
        "run_id": run.pk,
        "status": run.status,
        "created": run.advisories_created,
        "updated": run.advisories_updated,
        "errors": run.errors_count,
    }


@shared_task(name="ghsa.tasks.run_ghsa_sync_all")
def run_ghsa_sync_all(user_id=None) -> dict:
    user = _resolve_user(user_id)
    run = services.sync_ghsas_for_all_projects(by=user)
    return {
        "run_id": run.pk,
        "status": run.status,
        "created": run.advisories_created,
        "updated": run.advisories_updated,
        "errors": run.errors_count,
    }


@shared_task(name="ghsa.tasks.run_single_ghsa_sync")
def run_single_ghsa_sync(advisory_id: str, user_id=None) -> dict:
    advisory = Advisory.objects.get(advisory_id=advisory_id)
    user = _resolve_user(user_id)
    return services.sync_single_ghsa(advisory, by=user)


@shared_task(name="ghsa.tasks.run_cve_push")
def run_cve_push(task_id: int) -> dict:
    task = GhsaCvePushTask.objects.get(pk=task_id)
    result = services.push_reserved_cve_to_ghsa(task)
    return {"task_id": result.pk, "status": result.status}


@shared_task(name="ghsa.tasks.process_webhook")
def process_webhook(delivery_pk: int, payload: dict) -> dict:
    """Apply a verified webhook payload to local state.

    Signature is already validated by the receiver (see
    :func:`ghsa.webhooks.webhook`). The receiver also created the
    ``WebhookDelivery`` row; we only need to dispatch and stamp the
    final status.
    """
    delivery = WebhookDelivery.objects.get(pk=delivery_pk)
    services.dispatch_webhook(delivery, payload)
    delivery.refresh_from_db()
    return {"delivery_id": delivery.delivery_id, "status": delivery.status}
