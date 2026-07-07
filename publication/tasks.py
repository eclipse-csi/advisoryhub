"""Celery task that runs a publication: build → validate → push → flip state.

The advisory's ``state`` is flipped to ``published`` ONLY inside the
``mark_succeeded`` branch after Git push has reported a non-error
``PushInfo``. On any failure (validation, clone, write, commit, push) the
advisory keeps its previous state, the task is marked ``failed``, the
error is redacted before being persisted, and the dashboard surfaces it.
"""

from __future__ import annotations

import logging

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from advisories.models import Advisory, State
from audit.models import Action
from audit.services import record
from common import metrics
from common.enqueue import safe_enqueue

from . import csaf as csaf_builder
from . import cve as cve_builder
from . import osv as osv_builder
from . import services
from .git_service import GitPublicationError, WrittenFile, publish_files
from .models import (
    PublicationArtifact,
    PublicationTask,
    PublicationTaskStatus,
)
from .repo_config import active_config

log = logging.getLogger(__name__)


# acks_late + reject_on_worker_lost: a worker lost BEFORE the task starts re-delivers
# (the QUEUED/FAILED guard below lets it re-run). soft_time_limit fires a catchable
# SoftTimeLimitExceeded (handled by the broad `except` → marked FAILED, operator-retryable)
# so a hung git clone/push doesn't run until the broker's visibility_timeout (3600s) and
# get double-delivered; the hard time_limit is a backstop. Tune the limits to the repo size.
# A worker lost AFTER the task starts (hard time_limit SIGKILL, OOM kill, pod eviction)
# leaves the row 'running' — the redelivered message no-ops against the guard — and is
# recovered by the beat-scheduled reaper (reap_stale_publication_tasks, INV-PUB-7).
@shared_task(
    name="publication.run_publication",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    soft_time_limit=600,
    time_limit=660,
)
def run_publication(self, task_id: int) -> str:
    """Run a publication task end-to-end. Returns the task's final status."""
    try:
        task = PublicationTask.objects.select_related(
            "advisory", "version", "advisory__project"
        ).get(pk=task_id)
    except PublicationTask.DoesNotExist:
        return "missing"

    if task.status not in (PublicationTaskStatus.QUEUED, PublicationTaskStatus.FAILED):
        return task.status

    services.mark_running(task)
    if getattr(self, "request", None) and self.request.id:
        task.celery_task_id = self.request.id
        task.save(update_fields=["celery_task_id"])

    try:
        config = active_config()

        # A pinned version carrying ``withdrawn_reason`` is a *withdrawal*: the
        # OSV/CSAF carry the withdrawn marker and any assigned CVE record is
        # re-exported REJECTED rather than re-asserted PUBLISHED (INV-WITHDRAW).
        # Computed up front so the CVE build (step 1) can pick the right shape.
        withdrawn_reason = task.version.payload.get("withdrawn_reason")
        is_withdrawal = bool(withdrawn_reason)

        # 1. Build OSV / CSAF
        osv_doc = osv_builder.build_osv(task.version)
        osv_builder.validate_osv(osv_doc)
        record(
            action=Action.PUBLICATION_OSV_GENERATED,
            advisory=task.advisory,
            new_value={"task_id": task.pk},
        )
        metrics.publication_stage_total.labels(stage="osv_generated").inc()

        csaf_doc = csaf_builder.build_csaf(task.version)
        csaf_builder.validate_csaf(csaf_doc)
        record(
            action=Action.PUBLICATION_CSAF_GENERATED,
            advisory=task.advisory,
            new_value={"task_id": task.pk},
        )
        metrics.publication_stage_total.labels(stage="csaf_generated").inc()

        # A CVE record is exported only when the Eclipse Foundation has
        # assigned a CVE to this advisory. The id is read from the pinned
        # version payload (INV-VERSION-3), never live form data. On a
        # withdrawal it is re-exported REJECTED (rejectedReasons = the
        # withdrawal reason) so the repo mirrors the cve.org rejection.
        cve_doc = None
        cve_path = None
        assigned_cve = task.version.payload.get("assigned_cve_id")
        if assigned_cve:
            if is_withdrawal:
                cve_doc = cve_builder.build_rejected_cve(
                    task.version,
                    assigner_org_id=config.cve_assigner_org_id,
                    assigner_short_name=config.cve_assigner_short_name,
                    reason=withdrawn_reason,
                )
            else:
                cve_doc = cve_builder.build_cve(
                    task.version,
                    assigner_org_id=config.cve_assigner_org_id,
                    assigner_short_name=config.cve_assigner_short_name,
                )
            cve_builder.validate_cve(cve_doc)
            cve_path = config.cve_path(assigned_cve)
            record(
                action=Action.PUBLICATION_CVE_GENERATED,
                advisory=task.advisory,
                new_value={"task_id": task.pk, "cve_id": assigned_cve, "rejected": is_withdrawal},
            )
            metrics.publication_stage_total.labels(stage="cve_generated").inc()

        # 2. Persist generated documents to PublicationArtifact (the
        # single source of truth for what we pushed). The pinned
        # AdvisoryVersion provides the immutable input payload.
        # OSV/CSAF files are bucketed by the advisory's publication year.
        # The advisory id is intentionally opaque (no year inside it), so the
        # bucket comes from ``published_at`` — set once, on the first
        # successful publish (INV-LIFECYCLE-3). On that first run it is still
        # ``None`` here (it is set in step 4, after the push), so we fall back
        # to "now": the same calendar year ``published_at`` is about to be
        # stamped with. On every later re-publish ``published_at`` is already
        # set, so the path stays stable and never moves between buckets.
        pub_year = (task.advisory.published_at or timezone.now()).year
        osv_path = config.osv_path(task.advisory.advisory_id, pub_year)
        csaf_path = config.csaf_path(task.advisory.advisory_id, pub_year)
        PublicationArtifact.objects.update_or_create(
            task=task,
            kind=PublicationArtifact.Kind.OSV,
            defaults={"path": osv_path, "content": osv_doc},
        )
        PublicationArtifact.objects.update_or_create(
            task=task,
            kind=PublicationArtifact.Kind.CSAF,
            defaults={"path": csaf_path, "content": csaf_doc},
        )
        if cve_doc is not None and cve_path is not None:
            PublicationArtifact.objects.update_or_create(
                task=task,
                kind=PublicationArtifact.Kind.CVE,
                defaults={"path": cve_path, "content": cve_doc},
            )

        # 3. Push to Git
        files = [
            WrittenFile(path=osv_path, content=osv_builder.serialize_osv(osv_doc)),
            WrittenFile(path=csaf_path, content=csaf_builder.serialize_csaf(csaf_doc)),
        ]
        if cve_doc is not None and cve_path is not None:
            files.append(WrittenFile(path=cve_path, content=cve_builder.serialize_cve(cve_doc)))
        result = publish_files(
            config=config,
            files=files,
            commit_message=f"Publish advisory {task.advisory.advisory_id}",
        )
        record(
            action=Action.PUBLICATION_GIT_COMMIT,
            advisory=task.advisory,
            new_value={"commit_sha": result.commit_sha},
            metadata={"task_id": task.pk, "branch": result.pushed_to},
        )
        metrics.publication_stage_total.labels(stage="git_commit").inc()
        record(
            action=Action.PUBLICATION_GIT_PUSH,
            advisory=task.advisory,
            new_value={"commit_sha": result.commit_sha, "branch": result.pushed_to},
            metadata={"task_id": task.pk},
        )
        metrics.publication_stage_total.labels(stage="git_push").inc()

        # 4. Flip advisory state — only after a successful push. A pinned
        # version carrying ``withdrawn_reason`` is a *withdrawal*: the OSV/CSAF
        # just pushed carry the withdrawn marker (and any CVE record was
        # re-exported REJECTED), so the advisory lands in ``dismissed`` rather
        # than ``published`` (INV-LIFECYCLE-4) — the documents stay in the repo,
        # never deleted.
        with transaction.atomic():
            advisory = Advisory.objects.select_for_update().get(pk=task.advisory_id)
            previous_state = advisory.state
            if is_withdrawal:
                reason = withdrawn_reason
                advisory.state = State.DISMISSED
                advisory.dismissed_from_state = previous_state
                advisory.dismissed_reason = reason
                advisory.republish_required = False
                advisory.save(
                    update_fields=[
                        "state",
                        "dismissed_from_state",
                        "dismissed_reason",
                        "republish_required",
                        "modified_at",
                    ]
                )
                services.mark_succeeded(task, commit_sha=result.commit_sha)
                record(
                    action=Action.ADVISORY_DISMISSED,
                    actor=task.enqueued_by,
                    advisory=advisory,
                    metadata={"withdrawn": True, "reason": reason, "from_state": previous_state},
                )
                record(
                    action=Action.ADVISORY_STATE_CHANGED,
                    actor=task.enqueued_by,
                    advisory=advisory,
                    previous_value={"state": previous_state},
                    new_value={"state": State.DISMISSED, "withdrawn": True},
                    # The ADVISORY_DISMISSED row above narrates this withdrawal on
                    # the timeline; this structured twin is ledger-only (see
                    # advisories.timeline.events_for_advisory).
                    metadata={"narrated": True},
                )
                # A withdrawn advisory's CVE becomes an orphan (admin marks it
                # rejected at cve.org). State is already DISMISSED, so the
                # non-gated orphan helper won't re-flag republish_required.
                if advisory.assigned_cve_id:
                    from workflows.services import orphan_cve

                    orphan_cve(
                        advisory, by=task.enqueued_by, reason=f"Advisory withdrawn: {reason}"
                    )
                record(
                    action=Action.PUBLICATION_EXPORT_COMPLETED,
                    advisory=advisory,
                    new_value={
                        "task_id": task.pk,
                        "commit_sha": result.commit_sha,
                        "withdrawn": True,
                    },
                )
            else:
                advisory.state = State.PUBLISHED
                if advisory.published_at is None:
                    advisory.published_at = timezone.now()
                advisory.republish_required = False
                advisory.save(
                    update_fields=["state", "published_at", "republish_required", "modified_at"]
                )
                services.mark_succeeded(task, commit_sha=result.commit_sha)
                record(
                    action=Action.ADVISORY_PUBLISHED,
                    actor=task.enqueued_by,
                    advisory=advisory,
                    previous_value={"state": previous_state},
                    new_value={"state": State.PUBLISHED, "commit_sha": result.commit_sha},
                )
                # Publishing exits draft — clear any pending admin-reassignment
                # request (INV-AUTH-9: cleared on every exit from draft).
                from advisories import services as advisory_services

                advisory_services.clear_reassignment_request_if_pending(
                    advisory, by=task.enqueued_by, cause="published"
                )
                record(
                    action=Action.PUBLICATION_EXPORT_COMPLETED,
                    advisory=advisory,
                    new_value={"task_id": task.pk, "commit_sha": result.commit_sha},
                )

        # 5. Notify (best-effort) — a withdrawal is not a "published" event.
        if not is_withdrawal:
            from notifications.tasks import send_advisory_event_email

            safe_enqueue(send_advisory_event_email, advisory.pk, "advisory_published")

        return PublicationTaskStatus.SUCCEEDED

    except (
        osv_builder.OsvValidationError,
        csaf_builder.CsafValidationError,
        cve_builder.CveValidationError,
        cve_builder.CveBuildError,
    ) as exc:
        return _fail(task, error=f"validation: {exc}", action=Action.PUBLICATION_EXPORT_FAILED)
    except GitPublicationError as exc:
        return _fail(task, error=f"git: {exc}", action=Action.PUBLICATION_GIT_PUSH_FAILED)
    except Exception as exc:  # pragma: no cover — last-resort safety net
        log.exception("Unexpected publication failure")
        return _fail(task, error=f"unexpected: {exc}", action=Action.PUBLICATION_EXPORT_FAILED)


def _fail(task: PublicationTask, *, error: str, action: str) -> str:
    services.mark_failed(task, error=error)
    if action == Action.PUBLICATION_GIT_PUSH_FAILED:
        metrics.publication_stage_total.labels(stage="git_push_failed").inc()
    # task.last_error is already redacted; pass it through audit (which redacts again)
    record(
        action=action,
        advisory=task.advisory,
        new_value={"task_id": task.pk},
        metadata={"task_id": task.pk, "error": task.last_error},
    )
    # Best-effort notification of watchers about the failure.
    from notifications.tasks import send_advisory_event_email

    safe_enqueue(send_advisory_event_email, task.advisory_id, "publication_export_status")
    return PublicationTaskStatus.FAILED


# No acks_late / time limits: the reaper is idempotent and fast (one indexed
# SELECT, normally zero rows) and beat re-fires it every 10 minutes anyway.
@shared_task(name="publication.reap_stale_publication_tasks")
def reap_stale_publication_tasks() -> dict:
    """Beat (every 10 min): fail PublicationTask rows orphaned in queued/running.

    Covers the two holes acks_late/soft_time_limit cannot: a worker
    hard-killed mid-run that never reaches mark_failed, and an enqueue
    swallowed by safe_enqueue during a broker outage. See INV-PUB-7 and
    services.reap_stale_tasks for the threshold rationale.
    """
    return services.reap_stale_tasks()
