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


@shared_task(name="publication.run_publication", bind=True)
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

        # 1. Build OSV / CSAF
        osv_doc = osv_builder.build_osv(task.version)
        osv_builder.validate_osv(osv_doc)
        record(
            action=Action.PUBLICATION_OSV_GENERATED,
            advisory=task.advisory,
            new_value={"task_id": task.pk},
        )

        csaf_doc = csaf_builder.build_csaf(task.version)
        csaf_builder.validate_csaf(csaf_doc)
        record(
            action=Action.PUBLICATION_CSAF_GENERATED,
            advisory=task.advisory,
            new_value={"task_id": task.pk},
        )

        # A CVE record is exported only when the Eclipse Foundation has
        # assigned a CVE to this advisory. The id is read from the pinned
        # version payload (INV-VERSION-3), never live form data.
        cve_doc = None
        cve_path = None
        assigned_cve = task.version.payload.get("assigned_cve_id")
        if assigned_cve:
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
                new_value={"task_id": task.pk, "cve_id": assigned_cve},
            )

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
        record(
            action=Action.PUBLICATION_GIT_PUSH,
            advisory=task.advisory,
            new_value={"commit_sha": result.commit_sha, "branch": result.pushed_to},
            metadata={"task_id": task.pk},
        )

        # 4. Flip advisory state — only after a successful push.
        with transaction.atomic():
            advisory = Advisory.objects.select_for_update().get(pk=task.advisory_id)
            previous_state = advisory.state
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
            record(
                action=Action.PUBLICATION_EXPORT_COMPLETED,
                advisory=advisory,
                new_value={"task_id": task.pk, "commit_sha": result.commit_sha},
            )

        # 5. Notify (best-effort)
        try:
            from notifications.tasks import send_advisory_event_email

            send_advisory_event_email.delay(advisory.pk, "advisory_published")
        except Exception:  # pragma: no cover
            log.exception("Failed to enqueue advisory_published notification")

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
    # task.last_error is already redacted; pass it through audit (which redacts again)
    record(
        action=action,
        advisory=task.advisory,
        new_value={"task_id": task.pk},
        metadata={"task_id": task.pk, "error": task.last_error},
    )
    # Best-effort notification of watchers about the failure.
    try:
        from notifications.tasks import send_advisory_event_email

        send_advisory_event_email.delay(task.advisory_id, "publication_export_status")
    except Exception:  # pragma: no cover
        pass
    return PublicationTaskStatus.FAILED
