"""Service-layer orchestration for the GHSA integration.

The shape mirrors ``publication.services``: thin Celery wrappers in
``tasks.py``, side-effect-bearing logic here, no DB writes in
``client.py`` / ``translator.py``. Every external-system call goes
through a redacted audit entry so a leaked token never lands in the
audit table.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from functools import partial

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from advisories import services as advisory_services
from advisories.models import Advisory, GhsaCvePushStatus, GhsaState, Kind, State
from audit.models import Action
from audit.services import record, redact_secrets
from common.users import actor_or_none
from projects.models import Project, ProjectGitHubRepository

from .client import GitHubApiError, get_client
from .models import (
    GhsaCvePushTask,
    GhsaCvePushTaskStatus,
    GhsaSyncRun,
    GhsaSyncRunScope,
    GhsaSyncRunStatus,
    GitHubAppAccountType,
    GitHubAppInstallation,
    WebhookDelivery,
    WebhookDeliveryStatus,
)
from .pmi import PmiApiError, fetch_project_repos
from .translator import apply_ghsa_to_advisory

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PMI mirror
# ---------------------------------------------------------------------------


@transaction.atomic
def sync_project_repos_from_pmi(project: Project, *, by) -> int:
    """Mirror PMI's GitHub-repo list for ``project`` into the local table.

    Returns the number of *active* repo rows after the sync. Rows that
    disappear from PMI are soft-removed (``soft_removed_at`` set) so that
    historical advisories that still reference them keep a valid lookup.
    Rows that reappear are reactivated.

    PMI failures don't raise — they're recorded on the project (so the
    project page can surface a "stale" banner) and re-tried on the next
    beat tick.
    """
    now = timezone.now()
    try:
        repos = fetch_project_repos(project.slug)
    except PmiApiError as exc:
        project.last_pmi_sync_error = redact_secrets(str(exc))[:8000]
        project.save(update_fields=["last_pmi_sync_error"])
        record(
            action=Action.PMI_PROJECT_REPOS_SYNCED,
            actor=by,
            metadata={"project_slug": project.slug, "status": "failed"},
            new_value={"error": project.last_pmi_sync_error},
        )
        logger.warning("PMI sync failed for %s: %s", project.slug, project.last_pmi_sync_error)
        return project.github_repositories.filter(soft_removed_at__isnull=True).count()

    fresh: set[tuple[str, str]] = set(repos)
    existing = {(r.owner, r.name): r for r in project.github_repositories.all()}
    seen_keys: set[tuple[str, str]] = set()
    for owner, name in fresh:
        key = (owner, name)
        seen_keys.add(key)
        row = existing.get(key)
        if row is None:
            ProjectGitHubRepository.objects.create(
                project=project,
                owner=owner,
                name=name,
                last_seen_in_pmi_at=now,
            )
        else:
            row.last_seen_in_pmi_at = now
            row.soft_removed_at = None
            row.save(update_fields=["last_seen_in_pmi_at", "soft_removed_at"])

    # Anything previously known but absent now → soft-remove (idempotent).
    for key, row in existing.items():
        if key not in seen_keys and row.soft_removed_at is None:
            row.soft_removed_at = now
            row.save(update_fields=["soft_removed_at"])

    # PMI is authoritative for the repo↔project mapping. Now that the mirror
    # reflects the current mapping, re-home any GHSA-linked advisory whose repo
    # PMI now lists under this project but that still sits elsewhere — the only
    # sanctioned project change for a GHSA-linked advisory (INV-GHSA-1).
    reassigned = _reassign_ghsa_advisories_following_pmi(project, fresh, by=by, now=now)

    project.last_pmi_sync_at = now
    project.last_pmi_sync_error = ""
    project.save(update_fields=["last_pmi_sync_at", "last_pmi_sync_error"])

    record(
        action=Action.PMI_PROJECT_REPOS_SYNCED,
        actor=by,
        metadata={
            "project_slug": project.slug,
            "status": "succeeded",
            "active_repos": len(fresh),
            "advisories_reassigned": reassigned,
        },
    )
    return project.github_repositories.filter(soft_removed_at__isnull=True).count()


def _reassign_ghsa_advisories_following_pmi(
    project: Project, fresh_keys: set[tuple[str, str]], *, by, now
) -> int:
    """Re-home GHSA-linked advisories whose repo PMI now maps to ``project``.

    For each ``(owner, name)`` PMI currently lists under ``project``, move any
    GHSA-linked advisory bound to that repo whose project differs — *unless*
    the advisory's current project still actively mirrors the same repo. That
    last case is a transient mid-move state (the old project's stale row hasn't
    been soft-removed yet) or a genuine PMI double-listing; either way we defer
    rather than tug-of-war, and it reconciles on a later tick once the stale
    claim clears.

    This is the sole sanctioned project change for a GHSA-linked advisory
    (INV-GHSA-1). It saves via ``update_fields`` so it bypasses the
    ``Advisory.clean`` guard that blocks human/admin edits, and mirrors the
    side-effects of :func:`advisories.services.reassign_triage_project`:
    append a version (``project_slug`` is payload-visible), stamp the
    access-review banner, and flag ``republish_required`` when published. The
    review approval is intentionally preserved — the security content is
    unchanged, only the owning project moved. ``by`` is the system actor
    (``None``) on the beat path.
    """
    reassigned = 0
    for owner, name in fresh_keys:
        movers = (
            Advisory.objects.select_for_update()
            .filter(kind=Kind.GHSA_LINKED, ghsa_owner=owner, ghsa_repo=name)
            .exclude(project=project)
        )
        for advisory in movers:
            if ProjectGitHubRepository.objects.filter(
                project=advisory.project_id,
                owner=owner,
                name=name,
                soft_removed_at__isnull=True,
            ).exists():
                logger.info(
                    "PMI re-home deferred for %s: repo %s/%s still active under %s",
                    advisory.advisory_id,
                    owner,
                    name,
                    advisory.project.slug,
                )
                continue
            previous_project = advisory.project
            advisory.project = project
            if advisory.state == State.PUBLISHED:
                advisory.republish_required = True
            advisory.access_review_required_at = now
            advisory.save(
                update_fields=[
                    "project",
                    "republish_required",
                    "access_review_required_at",
                    "modified_at",
                ]
            )
            advisory_services.record_advisory_version(advisory, editor=by, if_changed=True)
            record(
                action=Action.ADVISORY_PROJECT_CHANGED,
                actor=by,
                advisory=advisory,
                previous_value={"project_slug": previous_project.slug},
                new_value={"project_slug": project.slug},
                metadata={
                    "advisory_id": advisory.advisory_id,
                    "reason": "pmi_repo_reassignment",
                },
            )
            transaction.on_commit(
                partial(advisory_services.queue_advisory_created_notification, advisory.pk)
            )
            reassigned += 1
            logger.info(
                "PMI re-homed %s from %s to %s (repo %s/%s)",
                advisory.advisory_id,
                previous_project.slug,
                project.slug,
                owner,
                name,
            )
    return reassigned


# ---------------------------------------------------------------------------
# Single-advisory sync
# ---------------------------------------------------------------------------


@transaction.atomic
def sync_single_ghsa(advisory: Advisory, *, by) -> dict:
    """Re-fetch the linked GHSA and project its content onto the advisory.

    Returns a small summary dict ``{changed: [...], conflict: bool}``.
    Raises if the advisory is not GHSA-linked or the GHSA was deleted.
    The caller decides whether to ``raise_for_publish`` afterwards.
    """
    if advisory.kind != Kind.GHSA_LINKED:
        raise ValueError("sync_single_ghsa called on a non-GHSA-linked advisory")
    if not (advisory.ghsa_id and advisory.ghsa_owner and advisory.ghsa_repo):
        raise ValueError("GHSA-linked advisory is missing ghsa_id/owner/repo")

    client = get_client()
    payload = client.get_advisory(advisory.ghsa_owner, advisory.ghsa_repo, advisory.ghsa_id)
    if payload is None:
        # GHSA was deleted upstream. Don't auto-dismiss; surface as state
        # change so the owner can decide.
        previous_state = advisory.ghsa_state
        advisory.ghsa_state = GhsaState.CLOSED
        advisory.ghsa_metadata = {"missing_upstream": True}
        advisory.ghsa_metadata_synced_at = timezone.now()
        advisory.save(
            update_fields=[
                "ghsa_state",
                "ghsa_metadata",
                "ghsa_metadata_synced_at",
                "modified_at",
            ]
        )
        record(
            action=Action.GHSA_METADATA_FETCHED,
            actor=by,
            advisory=advisory,
            previous_value={"ghsa_state": previous_state},
            new_value={"ghsa_state": advisory.ghsa_state, "missing_upstream": True},
            metadata={"ghsa_id": advisory.ghsa_id},
        )
        return {"changed": [], "conflict": False, "missing_upstream": True}

    result = apply_ghsa_to_advisory(advisory, payload)
    previous_ghsa_state = advisory.ghsa_state
    advisory.ghsa_state = result.ghsa_state
    advisory.ghsa_metadata = payload
    advisory.ghsa_metadata_synced_at = timezone.now()

    # CVE conflict detection. We never overwrite our own assigned_cve_id;
    # if GHSA carries something else, flag it and let an admin reconcile.
    conflict = False
    upstream_cve = result.cve_id_from_ghsa or ""
    if advisory.assigned_cve_id:
        if upstream_cve and upstream_cve != advisory.assigned_cve_id:
            conflict = True
            advisory.ghsa_cve_conflict_detected_at = timezone.now()
            advisory.ghsa_cve_conflict_ghsa_value = upstream_cve[:64]
        elif upstream_cve == advisory.assigned_cve_id and advisory.ghsa_cve_conflict_detected_at:
            # Conflict resolved (e.g. our push back to GHSA finally landed).
            advisory.ghsa_cve_conflict_detected_at = None
            advisory.ghsa_cve_conflict_ghsa_value = ""
    else:
        # AdvisoryHub has no assigned CVE yet. We deliberately *do not*
        # auto-import the GHSA's cve_id into our authoritative slot —
        # ``assigned_cve_id`` is reserved for values that came out of the
        # EF CNA workflow. If admins want to adopt the GHSA value, they
        # can run the request_cve flow and pick the same id.
        pass

    # If the advisory is already published and synced content changed, flag
    # for re-publication so the dashboard surfaces the action.
    if result.changed_field_names and advisory.state == State.PUBLISHED:
        advisory.republish_required = True
    advisory.save()

    # Append a new AdvisoryVersion when synced GHSA content moved an
    # OSV-shaped field. ``changed_field_names`` is the authoritative
    # signal here — using a raw payload diff would record a fresh row on
    # every poll because ``ghsa_metadata_synced_at`` is part of the
    # payload and changes on every sync.
    if result.changed_field_names:
        advisory_services.record_advisory_version(advisory, editor=by)

    record(
        action=Action.GHSA_METADATA_FETCHED,
        actor=by,
        advisory=advisory,
        previous_value={"ghsa_state": previous_ghsa_state},
        new_value={
            "ghsa_state": advisory.ghsa_state,
            "changed_fields": result.changed_field_names,
            "conflict": conflict,
        },
        metadata={"ghsa_id": advisory.ghsa_id},
    )
    if conflict:
        record(
            action=Action.GHSA_CVE_CONFLICT_DETECTED,
            actor=by,
            advisory=advisory,
            previous_value={"assigned_cve_id": advisory.assigned_cve_id},
            new_value={"ghsa_cve_id": upstream_cve},
            metadata={"ghsa_id": advisory.ghsa_id},
        )
    return {
        "changed": result.changed_field_names,
        "conflict": conflict,
        "missing_upstream": False,
    }


# ---------------------------------------------------------------------------
# Discovery / create
# ---------------------------------------------------------------------------


@transaction.atomic
def create_ghsa_linked_advisory(
    *,
    project: Project,
    ghsa_id: str,
    owner: str,
    repo: str,
    by,
) -> Advisory:
    """Create a draft GHSA-linked advisory and run an initial sync.

    The GHSA id is globally unique; if an advisory already exists for it,
    we return the existing row (idempotent — important for project-wide
    discovery sync).
    """
    existing = Advisory.objects.filter(ghsa_id=ghsa_id).first()
    if existing is not None:
        return existing
    advisory = Advisory.objects.create(
        project=project,
        state=State.DRAFT,
        kind=Kind.GHSA_LINKED,
        ghsa_id=ghsa_id,
        ghsa_owner=owner,
        ghsa_repo=repo,
        created_by=actor_or_none(by),
    )
    # v1 is seeded by the advisories.signals post_save hook. The initial
    # GHSA sync below may append v2 once metadata arrives from GitHub.
    record(
        action=Action.GHSA_LINKED_ADVISORY_CREATED,
        actor=by,
        advisory=advisory,
        new_value={"ghsa_id": ghsa_id, "owner": owner, "repo": repo},
        metadata={"project_slug": project.slug},
    )
    try:
        sync_single_ghsa(advisory, by=by)
    except GitHubApiError as exc:
        # We've created the row but couldn't sync. Leave the metadata
        # blank and let the dashboard surface a "sync failed" status;
        # the row itself is still useful (admins can retry).
        advisory.ghsa_metadata = {"sync_error": redact_secrets(str(exc))}
        advisory.save(update_fields=["ghsa_metadata", "modified_at"])
    # Best-effort duplicate detection on the freshly synced content (no-op
    # while disabled, never fails the sync). The idempotent `return existing`
    # above keeps re-discovered GHSAs from re-triggering checks.
    from similarity.services import request_check_safe

    request_check_safe(advisory, by=by)
    return advisory


@transaction.atomic
def sync_ghsas_for_project(project: Project, *, by) -> GhsaSyncRun:
    """List every GHSA in every active repo of ``project`` and reconcile.

    Discovers new GHSAs (auto-creates draft GHSA-linked advisories) and
    refreshes metadata for those already linked. Reports a
    :class:`GhsaSyncRun` row with counters so the dashboard can render the
    last run's outcome.
    """
    run = GhsaSyncRun.objects.create(
        scope=GhsaSyncRunScope.PROJECT,
        project=project,
        requested_by=actor_or_none(by),
        status=GhsaSyncRunStatus.RUNNING,
    )
    record(
        action=Action.GHSA_SYNC_RUN_STARTED,
        actor=by,
        metadata={"scope": run.scope, "project_slug": project.slug, "run_id": run.pk},
    )
    repos = list(project.github_repositories.filter(soft_removed_at__isnull=True))
    created = 0
    updated = 0
    errors = 0
    last_error = ""
    client = get_client()
    for repo_row in repos:
        try:
            for item in client.list_repo_advisories(
                repo_row.owner,
                repo_row.name,
                state="draft,triage,published,closed,withdrawn",
            ):
                ghsa_id = (item.get("ghsa_id") or "").strip()
                if not ghsa_id:
                    continue
                existing = Advisory.objects.filter(ghsa_id=ghsa_id).first()
                if existing is None:
                    create_ghsa_linked_advisory(
                        project=project,
                        ghsa_id=ghsa_id,
                        owner=repo_row.owner,
                        repo=repo_row.name,
                        by=by,
                    )
                    created += 1
                else:
                    try:
                        sync_single_ghsa(existing, by=by)
                        updated += 1
                    except GitHubApiError as exc:
                        errors += 1
                        last_error = redact_secrets(str(exc))
        except GitHubApiError as exc:
            errors += 1
            last_error = redact_secrets(str(exc))
            logger.warning(
                "GHSA listing failed for %s/%s: %s", repo_row.owner, repo_row.name, last_error
            )
    run.advisories_created = created
    run.advisories_updated = updated
    run.errors_count = errors
    run.last_error = (last_error or "")[:8000]
    run.finished_at = timezone.now()
    run.status = (
        GhsaSyncRunStatus.FAILED
        if errors and created == 0 and updated == 0
        else (GhsaSyncRunStatus.PARTIAL if errors else GhsaSyncRunStatus.SUCCEEDED)
    )
    run.save()
    record(
        action=Action.GHSA_SYNC_RUN_FINISHED,
        actor=by,
        metadata={
            "scope": run.scope,
            "project_slug": project.slug,
            "run_id": run.pk,
            "status": run.status,
            "created": created,
            "updated": updated,
            "errors": errors,
        },
    )
    return run


@transaction.atomic
def sync_ghsas_for_all_projects(*, by, projects: Iterable[Project] | None = None) -> GhsaSyncRun:
    """Org-wide sync. Iterates every project that has at least one repo."""
    run = GhsaSyncRun.objects.create(
        scope=GhsaSyncRunScope.ALL,
        requested_by=actor_or_none(by),
        status=GhsaSyncRunStatus.RUNNING,
    )
    record(
        action=Action.GHSA_SYNC_RUN_STARTED,
        actor=by,
        metadata={"scope": run.scope, "run_id": run.pk},
    )
    if projects is None:
        projects = Project.objects.filter(
            github_repositories__soft_removed_at__isnull=True
        ).distinct()
    created = 0
    updated = 0
    errors = 0
    last_error = ""
    for project in projects:
        try:
            child = sync_ghsas_for_project(project, by=by)
        except Exception as exc:  # pragma: no cover — defensive
            errors += 1
            last_error = redact_secrets(str(exc))
            logger.exception("project sync failed for %s", project.slug)
            continue
        created += child.advisories_created
        updated += child.advisories_updated
        errors += child.errors_count
        if child.last_error:
            last_error = child.last_error
    run.advisories_created = created
    run.advisories_updated = updated
    run.errors_count = errors
    run.last_error = (last_error or "")[:8000]
    run.finished_at = timezone.now()
    run.status = (
        GhsaSyncRunStatus.FAILED
        if errors and created == 0 and updated == 0
        else (GhsaSyncRunStatus.PARTIAL if errors else GhsaSyncRunStatus.SUCCEEDED)
    )
    run.save()
    record(
        action=Action.GHSA_SYNC_RUN_FINISHED,
        actor=by,
        metadata={
            "scope": run.scope,
            "run_id": run.pk,
            "status": run.status,
            "created": created,
            "updated": updated,
            "errors": errors,
        },
    )
    return run


# ---------------------------------------------------------------------------
# CVE id push-back to GHSA
# ---------------------------------------------------------------------------


@transaction.atomic
def enqueue_cve_push(advisory: Advisory, cve_id: str, *, by) -> GhsaCvePushTask:
    """Create a queued :class:`GhsaCvePushTask` and audit the request.

    The Celery worker (``ghsa.tasks.run_cve_push``) picks it up and calls
    :func:`push_reserved_cve_to_ghsa`. Caller is responsible for
    wrapping the ``transaction.on_commit`` enqueue.
    """
    if advisory.kind != Kind.GHSA_LINKED:
        raise ValueError("CVE push only applies to GHSA-linked advisories")
    advisory.ghsa_cve_push_status = GhsaCvePushStatus.PENDING
    advisory.save(update_fields=["ghsa_cve_push_status", "modified_at"])
    task = GhsaCvePushTask.objects.create(
        advisory=advisory,
        cve_id=cve_id,
        requested_by=actor_or_none(by),
        status=GhsaCvePushTaskStatus.QUEUED,
    )
    record(
        action=Action.GHSA_CVE_PUSH_REQUESTED,
        actor=by,
        advisory=advisory,
        new_value={"cve_id": cve_id, "task_id": task.pk},
        metadata={"ghsa_id": advisory.ghsa_id},
    )
    return task


def push_reserved_cve_to_ghsa(task: GhsaCvePushTask) -> GhsaCvePushTask:
    """Run a single CVE push attempt — invoked by the Celery worker.

    On success: stamps ``Advisory.ghsa_cve_push_status=succeeded`` and the
    task status. On failure: marks the task failed with a redacted error
    message; AdvisoryHub's internal ``assigned_cve_id`` is **not** rolled
    back — the EF CVE allocation stands regardless of GitHub reachability.
    """
    task.refresh_from_db()
    advisory = task.advisory
    if task.status not in (GhsaCvePushTaskStatus.QUEUED, GhsaCvePushTaskStatus.FAILED):
        return task
    task.status = GhsaCvePushTaskStatus.RUNNING
    task.attempts = (task.attempts or 0) + 1
    task.started_at = timezone.now()
    task.save(update_fields=["status", "attempts", "started_at"])

    try:
        client = get_client()
        client.update_advisory_cve(
            advisory.ghsa_owner, advisory.ghsa_repo, advisory.ghsa_id, task.cve_id
        )
    except GitHubApiError as exc:
        msg = redact_secrets(str(exc))[:8000]
        task.status = GhsaCvePushTaskStatus.FAILED
        task.finished_at = timezone.now()
        task.last_error = msg
        task.save(update_fields=["status", "finished_at", "last_error"])
        advisory.ghsa_cve_push_status = GhsaCvePushStatus.FAILED
        advisory.ghsa_cve_push_attempted_at = timezone.now()
        advisory.save(
            update_fields=["ghsa_cve_push_status", "ghsa_cve_push_attempted_at", "modified_at"]
        )
        record(
            action=Action.GHSA_CVE_PUSH_FAILED,
            actor=task.requested_by,
            advisory=advisory,
            new_value={"task_id": task.pk, "cve_id": task.cve_id},
            metadata={"ghsa_id": advisory.ghsa_id, "error": msg},
        )
        return task

    task.status = GhsaCvePushTaskStatus.SUCCEEDED
    task.finished_at = timezone.now()
    task.last_error = ""
    task.save(update_fields=["status", "finished_at", "last_error"])
    advisory.ghsa_cve_push_status = GhsaCvePushStatus.SUCCEEDED
    advisory.ghsa_cve_push_attempted_at = timezone.now()
    # A successful push resolves any previously-flagged conflict.
    advisory.ghsa_cve_conflict_detected_at = None
    advisory.ghsa_cve_conflict_ghsa_value = ""
    advisory.save(
        update_fields=[
            "ghsa_cve_push_status",
            "ghsa_cve_push_attempted_at",
            "ghsa_cve_conflict_detected_at",
            "ghsa_cve_conflict_ghsa_value",
            "modified_at",
        ]
    )
    record(
        action=Action.GHSA_CVE_PUSH_SUCCEEDED,
        actor=task.requested_by,
        advisory=advisory,
        new_value={"task_id": task.pk, "cve_id": task.cve_id},
        metadata={"ghsa_id": advisory.ghsa_id},
    )
    return task


# ---------------------------------------------------------------------------
# GitHub App installation registry
# ---------------------------------------------------------------------------


def _extract_installation_fields(payload: dict) -> dict | None:
    """Pull (installation_id, account_login, account_type, app_slug) out of payload.

    Handles both the ``GET /app/installations`` response shape (top-level
    keys) and the webhook ``installation`` event shape (nested under
    ``installation.account``).
    """
    if not payload:
        return None
    installation_id = payload.get("id") or payload.get("installation_id")
    account = payload.get("account") or {}
    account_login = account.get("login") or payload.get("account_login")
    account_type = account.get("type") or payload.get("account_type") or "Organization"
    app_slug = payload.get("app_slug", "") or ""
    if not installation_id or not account_login:
        return None
    if account_type not in dict(GitHubAppAccountType.choices):
        account_type = GitHubAppAccountType.ORGANIZATION
    return {
        "installation_id": int(installation_id),
        "account_login": account_login,
        "account_type": account_type,
        "app_slug": app_slug,
    }


@transaction.atomic
def upsert_installation(payload: dict, *, by=None) -> GitHubAppInstallation | None:
    """Create or refresh a ``GitHubAppInstallation`` row from a GitHub payload.

    Returns the row (or ``None`` if the payload was unusable). Audits
    ``GHSA_INSTALLATION_REGISTERED`` only on first create — subsequent
    upserts just bump ``last_seen_at``.
    """
    fields = _extract_installation_fields(payload)
    if fields is None:
        return None
    now = timezone.now()
    row, created = GitHubAppInstallation.objects.get_or_create(
        installation_id=fields["installation_id"],
        defaults={
            "account_login": fields["account_login"],
            "account_type": fields["account_type"],
            "app_slug": fields["app_slug"],
            "last_seen_at": now,
        },
    )
    if not created:
        update_fields = ["last_seen_at"]
        row.last_seen_at = now
        # Keep the row in sync if GitHub renamed the account or our
        # earlier discovery filled in fewer fields. ``installation_id``
        # never changes for an installation, so it stays the lookup key.
        if row.account_login != fields["account_login"]:
            row.account_login = fields["account_login"]
            update_fields.append("account_login")
        if row.account_type != fields["account_type"]:
            row.account_type = fields["account_type"]
            update_fields.append("account_type")
        if not row.app_slug and fields["app_slug"]:
            row.app_slug = fields["app_slug"]
            update_fields.append("app_slug")
        if row.suspended_at is not None:
            # Re-appearing in /app/installations or a new webhook means
            # the install is active again.
            row.suspended_at = None
            update_fields.append("suspended_at")
        row.save(update_fields=update_fields)
    else:
        record(
            action=Action.GHSA_INSTALLATION_REGISTERED,
            actor=by,
            new_value={
                "installation_id": row.installation_id,
                "account_login": row.account_login,
                "account_type": row.account_type,
            },
        )
    return row


@transaction.atomic
def mark_installation_suspended(installation_id: int, *, suspended: bool, by=None) -> None:
    row = GitHubAppInstallation.objects.filter(installation_id=installation_id).first()
    if row is None:
        return
    if suspended:
        if row.suspended_at is None:
            row.suspended_at = timezone.now()
            row.save(update_fields=["suspended_at"])
            record(
                action=Action.GHSA_INSTALLATION_SUSPENDED,
                actor=by,
                metadata={"installation_id": installation_id, "account_login": row.account_login},
            )
    else:
        if row.suspended_at is not None:
            row.suspended_at = None
            row.save(update_fields=["suspended_at"])
            record(
                action=Action.GHSA_INSTALLATION_REGISTERED,
                actor=by,
                metadata={
                    "installation_id": installation_id,
                    "account_login": row.account_login,
                    "unsuspended": True,
                },
            )


@transaction.atomic
def remove_installation(installation_id: int, *, by=None) -> None:
    """Soft-remove an installation row by stamping ``suspended_at``.

    We don't hard-delete so historical advisories that still reference
    repos under this account retain a valid (if suspended) lookup row.
    """
    row = GitHubAppInstallation.objects.filter(installation_id=installation_id).first()
    if row is None:
        return
    if row.suspended_at is None:
        row.suspended_at = timezone.now()
        row.save(update_fields=["suspended_at"])
    record(
        action=Action.GHSA_INSTALLATION_REMOVED,
        actor=by,
        metadata={"installation_id": installation_id, "account_login": row.account_login},
    )


def discover_installations(*, by=None) -> list[GitHubAppInstallation]:
    """Pull every installation of the App from GitHub and upsert them.

    The backstop / cold-start path for the installation registry; the
    webhook listener keeps the registry fresh during normal operation.
    """
    client = get_client()
    payloads = client.list_installations()
    rows: list[GitHubAppInstallation] = []
    for payload in payloads:
        row = upsert_installation(payload, by=by)
        if row is not None:
            rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Webhook dispatch
# ---------------------------------------------------------------------------


def _mark_delivery(delivery: WebhookDelivery, status: str, *, error: str = "") -> None:
    delivery.status = status
    delivery.last_error = redact_secrets(error or "")[:8000]
    delivery.processed_at = timezone.now()
    delivery.save(update_fields=["status", "last_error", "processed_at"])


def dispatch_webhook(delivery: WebhookDelivery, payload: dict) -> None:
    """Apply a verified webhook payload to local state.

    Called from the ``process_webhook`` Celery task. Errors are captured
    on the delivery row (redacted) so retries are visible in the
    dashboard; raising would let Celery retry and double-process.
    """
    try:
        event = delivery.event
        action = (payload.get("action") or "").lower()
        if event == "installation":
            _dispatch_installation_event(action, payload)
        elif event == "installation_repositories":
            # PMI is the source-of-truth for project↔repo; we just log.
            logger.info(
                "installation_repositories.%s ignored (delivery=%s)",
                action,
                delivery.delivery_id,
            )
        elif event == "repository_advisory":
            _dispatch_repository_advisory_event(action, payload)
        else:
            _mark_delivery(delivery, WebhookDeliveryStatus.SKIPPED)
            return
        _mark_delivery(delivery, WebhookDeliveryStatus.PROCESSED)
    except Exception as exc:  # pragma: no cover — defensive
        logger.exception("webhook %s dispatch failed", delivery.delivery_id)
        _mark_delivery(delivery, WebhookDeliveryStatus.FAILED, error=str(exc))


def _dispatch_installation_event(action: str, payload: dict) -> None:
    install_payload = payload.get("installation") or {}
    if action in ("created", "unsuspend", "new_permissions_accepted"):
        upsert_installation(install_payload)
        # ``unsuspend`` also clears the suspended_at marker explicitly
        # (upsert_installation already handles the re-appearing case,
        # but be defensive in case GitHub's payload shape varies).
        installation_id = install_payload.get("id")
        if action == "unsuspend" and installation_id:
            mark_installation_suspended(int(installation_id), suspended=False)
    elif action == "suspend":
        installation_id = install_payload.get("id")
        if installation_id:
            mark_installation_suspended(int(installation_id), suspended=True)
    elif action == "deleted":
        installation_id = install_payload.get("id")
        if installation_id:
            remove_installation(int(installation_id))
    else:
        logger.info("installation.%s ignored", action)


def _dispatch_repository_advisory_event(action: str, payload: dict) -> None:
    advisory_payload = payload.get("repository_advisory") or {}
    repository = payload.get("repository") or {}
    ghsa_id = (advisory_payload.get("ghsa_id") or "").strip()
    full_name = (repository.get("full_name") or "").strip()
    if not ghsa_id or not full_name or "/" not in full_name:
        logger.info("repository_advisory.%s missing ghsa_id/repo, skipping", action)
        return
    owner, name = full_name.split("/", 1)

    existing = Advisory.objects.filter(ghsa_id=ghsa_id).first()
    if existing is not None:
        try:
            sync_single_ghsa(existing, by=None)
        except GitHubApiError as exc:
            logger.warning("webhook refresh for %s failed: %s", ghsa_id, redact_secrets(str(exc)))
        return

    # Auto-create only when the repo is actively mirrored from PMI.
    if action not in ("published", "updated", "edited", "reopened"):
        # withdrawn/closed events for unknown GHSAs aren't worth a row.
        return
    repo_row = ProjectGitHubRepository.objects.filter(
        owner=owner, name=name, soft_removed_at__isnull=True
    ).first()
    if repo_row is None:
        logger.info(
            "repository_advisory.%s for %s/%s skipped — not in PMI mirror",
            action,
            owner,
            name,
        )
        return
    try:
        create_ghsa_linked_advisory(
            project=repo_row.project,
            ghsa_id=ghsa_id,
            owner=owner,
            repo=name,
            by=None,
        )
    except GitHubApiError as exc:
        logger.warning("webhook auto-create for %s failed: %s", ghsa_id, redact_secrets(str(exc)))


# ---------------------------------------------------------------------------
# Publish-time hook
# ---------------------------------------------------------------------------


def refresh_for_publish(advisory: Advisory, *, by) -> None:
    """Pre-flight check called by ``publication.services.publish``.

    For a GHSA-linked advisory we refresh metadata from GitHub *before*
    the publication pins the version, so the OSV/CSAF export reflects
    the GHSA's current state. The refresh appends a new
    ``AdvisoryVersion`` if any synced content changed, so the publication
    task picks that up as the latest version. Blocks publication when:

    * the GHSA was deleted upstream (404),
    * the GHSA is not in ``published`` state,
    * a CVE conflict is currently flagged.

    Native advisories pass through unchanged.
    """
    if advisory.kind != Kind.GHSA_LINKED:
        return
    summary = sync_single_ghsa(advisory, by=by)
    if summary.get("missing_upstream"):
        raise PermissionDenied("Linked GHSA no longer exists on GitHub; cannot publish.")
    if advisory.ghsa_state != GhsaState.PUBLISHED:
        raise PermissionDenied(
            "Linked GHSA must be published on GitHub before AdvisoryHub can publish."
        )
    if advisory.ghsa_cve_conflict_detected_at is not None:
        raise PermissionDenied(
            "CVE id conflict between AdvisoryHub and the linked GHSA — reconcile first."
        )
