"""Write-path services for the advisory triage flow.

The public intake form creates an ``Advisory(state=TRIAGE)`` plus an
``AdvisoryIntakeMetadata`` sidecar. Triagers then either promote it to
``DRAFT``, dismiss it, reassign its project, or flag it for admin routing.
All five state-touching entry points live here so audit, notifications, and
permission re-checks stay consistent. Authorization is re-verified inside
each service — callers must have it, but services don't trust them.

Public-form abuse (honeypot, rate limits, captcha) is the form layer's job;
this module's invariant is: any row that lands here represents a real,
non-honeypot submission, and the caller has at least passed permission
checks at the view boundary.
"""

from __future__ import annotations

from functools import partial

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from audit.models import Action
from audit.services import record, record_from_request
from common.enqueue import safe_enqueue
from common.net import client_ip
from common.users import actor_or_none

from .models import Advisory, AdvisoryIntakeMetadata, AdvisoryVersion, State
from .permissions import (
    UNSORTED_PROJECT_SLUG,
    can_clear_admin_routing_flag,
    can_flag_for_admin_routing,
    can_reopen,
    can_triage,
    can_view,
    is_global_admin,
    is_security_team_member,
)

# ---- Submission (public, possibly anonymous) -------------------------------


def submit_triage_report(
    *,
    request,
    project,
    summary: str,
    details: str,
    reporter_display_name: str = "",
    aliases: list | None = None,
    cwe_ids: list | None = None,
    references: list | None = None,
    severity: list | None = None,
    credits: list | None = None,
    affected: list | None = None,
) -> Advisory:
    """Persist a public-form vulnerability report as a triage advisory.

    Always called with a resolved :class:`projects.models.Project` — the
    form fork (real project vs unsorted sentinel) happens at the form layer.
    Authentication state determines the reporter linkage and the auto-grant:

    * Authenticated: ``reporter_user`` set on the sidecar, viewer grant
      issued so the reporter sees the advisory immediately on their
      dashboard.
    * Anonymous: no reporter_user, no grant. The submitter cannot be
      re-associated with the advisory later — by design (we removed the
      free-text email field for this exact reason).

    The OSV-shaped list kwargs (``aliases``, ``cwe_ids``, ``references``,
    ``severity``, ``credits``, ``affected``) match the shape produced by
    :func:`advisories.form_assembly.assemble_json` so a reporter who
    expanded the public form's *Advanced* disclosure lands their structured
    data straight onto the resulting advisory — no re-keying at triage time.

    Honeypot submissions never reach this function — the view forks to
    :class:`intake.models.HoneypotSubmission` before getting here.
    """
    from access.models import Permission
    from access.services import grant_to_user

    reporter_user = request.user if request.user.is_authenticated else None
    ip = client_ip(request)
    ua = request.META.get("HTTP_USER_AGENT", "")[:512]
    is_unsorted = project.slug == UNSORTED_PROJECT_SLUG

    with transaction.atomic():
        advisory = Advisory(
            project=project,
            state=State.TRIAGE,
            summary=summary[:300],
            details=details,
            created_by=reporter_user,
            aliases=aliases or [],
            cwe_ids=cwe_ids or [],
            references=references or [],
            severity=severity or [],
            credits=credits or [],
            affected=affected or [],
        )
        # Run model-level validators (validate_aliases, validate_cwe_ids,
        # validate_affected, etc.) before save. The formset validators in
        # the view already cover the same ground; this is defence in depth
        # for any caller that bypasses the form/formset layer, and so that
        # reporter-supplied advanced fields can't sneak structurally
        # invalid JSON onto the curated row.
        advisory.full_clean(
            exclude={
                "advisory_id",  # generated in save()
                "created_by",  # nullable for anonymous submissions
                "submitted_for_review_by",
                "submitted_for_review_at",
                "published_at",
                "review_status",
            }
        )
        # v1 is seeded automatically by the post_save signal in
        # ``advisories.signals``; editor is taken from ``advisory.created_by``
        # which equals ``reporter_user`` (or ``None`` for anonymous reports).
        advisory.save()
        AdvisoryIntakeMetadata.objects.create(
            advisory=advisory,
            reporter_user=reporter_user,
            reporter_display_name=reporter_display_name[:200],
            submitted_ip=ip,
            submitted_user_agent=ua,
            needs_admin_routing=is_unsorted,
        )
        if reporter_user is not None:
            # Auto-grant viewer to the authenticated reporter. The grant is
            # active in TRIAGE state per the resolution order; the reporter
            # sees the advisory but can't comment until it's promoted.
            grant_to_user(advisory, reporter_user, Permission.VIEWER, by=None)

        record_from_request(
            request,
            action=Action.ADVISORY_TRIAGE_SUBMITTED,
            advisory=advisory,
            metadata={
                "advisory_id": advisory.advisory_id,
                "project_slug": project.slug,
                "authenticated": reporter_user is not None,
                "unsorted": is_unsorted,
            },
        )

        transaction.on_commit(
            partial(_enqueue_triage_notification, advisory.pk, "advisory_triage_submitted")
        )

    return advisory


# ---- Triager actions (state-locked to TRIAGE) ------------------------------


def promote_triage_to_draft(advisory: Advisory, *, by, project=None) -> Advisory:
    """Promote a triage advisory to ``state=DRAFT``.

    For unrouted advisories (on the ``unsorted`` sentinel project), the
    caller MUST supply an explicit target ``project`` — admins use this to
    route the report into the right project at promotion time. For already-
    routed reports, ``project`` may be omitted to keep the current project,
    or passed to reassign-as-part-of-promotion if the triager has authority
    on the target.

    Raises:
        PermissionDenied: caller lacks triage rights, or is reassigning to
            a project they aren't on the team of.
        ValueError: advisory is not in TRIAGE state, or unrouted advisory
            without an explicit target.
    """
    with transaction.atomic():
        locked = Advisory.objects.select_for_update().get(pk=advisory.pk)
        if not can_triage(by, locked):
            raise PermissionDenied("You may not triage this advisory.")
        if locked.state != State.TRIAGE:
            raise ValueError(f"Advisory is not in triage state (currently {locked.state}).")

        previous_project = locked.project
        is_unsorted_origin = previous_project.slug == UNSORTED_PROJECT_SLUG
        target_project = project or previous_project
        if is_unsorted_origin and (project is None or project.slug == UNSORTED_PROJECT_SLUG):
            raise ValueError(
                "Unrouted triage advisories require an explicit target project at promotion."
            )

        is_reassigning = previous_project != target_project
        if is_reassigning and not (
            is_global_admin(by) or is_security_team_member(by, target_project)
        ):
            raise PermissionDenied("You are not on the target project's security team.")

        locked.state = State.DRAFT
        locked.project = target_project
        locked.save(update_fields=["state", "project", "modified_at"])
        # Project change is payload-visible (project_slug); state-only flips
        # aren't. ``if_changed=True`` does the right thing for both.
        record_advisory_version(locked, editor=by, if_changed=True)

        # Clear the admin-routing flag on the sidecar — promotion resolves
        # any pending routing question by definition.
        intake = getattr(locked, "intake", None)
        if intake is not None and (
            intake.needs_admin_routing or intake.admin_routing_note or intake.flagged_for_routing_at
        ):
            _clear_routing_flag(intake)

        record(
            action=Action.ADVISORY_TRIAGE_PROMOTED,
            actor=by,
            advisory=locked,
            metadata={
                "advisory_id": locked.advisory_id,
                "previous_project_slug": previous_project.slug,
                "project_slug": target_project.slug,
                "reassigned": is_reassigning,
            },
        )
        record(
            action=Action.ADVISORY_STATE_CHANGED,
            actor=by,
            advisory=locked,
            previous_value={"state": State.TRIAGE},
            new_value={"state": State.DRAFT},
        )

        transaction.on_commit(
            partial(_enqueue_triage_notification, locked.pk, "advisory_triage_promoted")
        )

    return locked


def dismiss_triage(advisory: Advisory, *, by, reason: str) -> Advisory:
    """Dismiss a triage advisory (spam, duplicate, out-of-scope).

    Reuses the standard ``ADVISORY_DISMISSED`` audit action and the
    existing ``dismissed_reason`` field. The advisory persists at
    ``state=DISMISSED`` so its audit trail remains intact.
    """
    cleaned_reason = (reason or "").strip()
    if not cleaned_reason:
        raise ValueError("Dismissal reason is required.")

    with transaction.atomic():
        locked = Advisory.objects.select_for_update().get(pk=advisory.pk)
        if not can_triage(by, locked):
            raise PermissionDenied("You may not triage this advisory.")
        if locked.state != State.TRIAGE:
            raise ValueError(f"Advisory is not in triage state (currently {locked.state}).")

        locked.state = State.DISMISSED
        locked.dismissed_reason = cleaned_reason
        locked.dismissed_from_state = State.TRIAGE
        locked.save(
            update_fields=["state", "dismissed_reason", "dismissed_from_state", "modified_at"]
        )

        record(
            action=Action.ADVISORY_DISMISSED,
            actor=by,
            advisory=locked,
            metadata={
                "advisory_id": locked.advisory_id,
                "project_slug": locked.project.slug,
                "reason": cleaned_reason,
                "from_state": State.TRIAGE.value,
            },
        )
        record(
            action=Action.ADVISORY_STATE_CHANGED,
            actor=by,
            advisory=locked,
            previous_value={"state": State.TRIAGE},
            new_value={"state": State.DISMISSED},
        )

        # Symmetric with cancel_open_cve_request: tear down any pending
        # review state so a later reopen lands in a clean draft. Triage
        # advisories almost never carry a non-NONE review_status (the
        # workflow blocks submit_for_review pre-DRAFT), so this is a
        # defensive no-op in practice.
        from workflows.services import cancel_pending_review

        cancel_pending_review(locked, by=by, reason=cleaned_reason)

        transaction.on_commit(
            partial(_enqueue_triage_notification, locked.pk, "advisory_triage_dismissed")
        )

    return locked


def reopen_advisory(advisory: Advisory, *, by) -> Advisory:
    """Return a dismissed advisory to its pre-dismissal state.

    The destination state comes from ``advisory.dismissed_from_state`` (set
    by ``dismiss_triage`` and the draft-dismiss view; backfilled for older
    rows in the 0012 migration). State flips immediately even when CVE-side
    follow-up is still pending — the advisory can be a CVE-less ``draft``
    while an :class:`OrphanCveReassignmentTask` is queued separately for
    admin to resolve.

    Side effects, in order:

    1. ``CveRequestTask`` auto-restoration. If the most recent CVE request
       for this advisory is ``CANCELLED`` (the auto-cancel from the dismiss
       path) and the advisory currently has no other open request and no
       ``assigned_cve_id``, a fresh ``QUEUED`` task is created via
       :func:`workflows.services.request_cve` so the owner's pending work
       returns instead of vanishing.
    2. CVE assignment restoration. The latest :class:`OrphanCve` for this
       advisory drives the decision:

       * ``ORPHANED`` → CVE reattached immediately via
         :func:`workflows.services.reassign_orphan_cve`.
       * ``MARKED_REJECTED`` → an :class:`OrphanCveReassignmentTask` is
         queued for admin resolution.
       * ``REASSIGNED`` or no orphan → no-op.
    3. ``advisory_reopened`` notification queued post-commit.

    Permission re-checked at the boundary per ``INV-AUTH-1``.
    """
    from workflows.models import (
        CveRequestStatus,
        OrphanCve,
        OrphanCveReassignmentStatus,
        OrphanCveReassignmentTask,
        OrphanCveStatus,
    )
    from workflows.services import reassign_orphan_cve, request_cve

    with transaction.atomic():
        locked = Advisory.objects.select_for_update().get(pk=advisory.pk)
        if not can_reopen(by, locked):
            raise PermissionDenied("You may not reopen this advisory.")
        if locked.state != State.DISMISSED:
            raise ValueError(f"Advisory is not in dismissed state (currently {locked.state}).")

        target_state = locked.dismissed_from_state or State.DRAFT
        if target_state not in (State.TRIAGE, State.DRAFT):
            # Defensive: dismissed_from_state should never carry PUBLISHED
            # or DISMISSED, but guard against odd backfilled rows.
            target_state = State.DRAFT

        locked.state = target_state
        locked.save(update_fields=["state", "modified_at"])

        # Restore an auto-cancelled CVE request if there's no current open
        # request and no assigned CVE. Symmetric inverse of the
        # ``cancel_open_cve_request`` side-effect that fires on dismiss.
        # Only applies to draft target — triage advisories cannot hold CVE
        # requests in the first place (see ``can_request_cve``).
        cve_request_restored = False
        if (
            target_state == State.DRAFT
            and not locked.assigned_cve_id
            and not locked.cve_requests.filter(status=CveRequestStatus.QUEUED).exists()
        ):
            latest_cve_task = locked.cve_requests.order_by("-created_at").first()
            if latest_cve_task is not None and latest_cve_task.status == CveRequestStatus.CANCELLED:
                # request_cve re-checks ``can_request_cve`` (owner-only); reopen
                # has already flipped state to draft and the reopener is
                # owner-or-admin by ``can_reopen``, so the gate passes.
                request_cve(locked, by=by)
                cve_request_restored = True

        # Restore the CVE assignment from the most recent orphan for this
        # advisory. We process at most one orphan — the newest.
        orphan_disposition = "none"
        orphan = (
            OrphanCve.objects.filter(previous_advisory=locked).order_by("-unassigned_at").first()
        )
        if orphan is not None:
            if orphan.status == OrphanCveStatus.ORPHANED:
                try:
                    reassign_orphan_cve(orphan, by=by, advisory=locked)
                    orphan_disposition = "reassigned_direct"
                except ValueError:
                    # Conflict (e.g. CVE reassigned elsewhere, or advisory
                    # already holds a different CVE). Fall back to an admin
                    # task so a human resolves it.
                    OrphanCveReassignmentTask.objects.create(
                        orphan_cve=orphan,
                        advisory=locked,
                        requested_by=actor_or_none(by),
                    )
                    orphan_disposition = "queued_admin_task"
            elif orphan.status == OrphanCveStatus.MARKED_REJECTED:
                if not OrphanCveReassignmentTask.objects.filter(
                    orphan_cve=orphan,
                    status=OrphanCveReassignmentStatus.QUEUED,
                ).exists():
                    OrphanCveReassignmentTask.objects.create(
                        orphan_cve=orphan,
                        advisory=locked,
                        requested_by=actor_or_none(by),
                    )
                orphan_disposition = "queued_admin_task"
            elif orphan.status == OrphanCveStatus.REASSIGNED:
                orphan_disposition = "already_reassigned"

        if orphan_disposition == "queued_admin_task":
            record(
                action=Action.ORPHAN_REASSIGNMENT_REQUESTED,
                actor=by,
                advisory=locked,
                metadata={
                    "advisory_id": locked.advisory_id,
                    "orphan_id": orphan.pk if orphan else None,
                    "orphan_status": orphan.status if orphan else None,
                },
            )

        record(
            action=Action.ADVISORY_REOPENED,
            actor=by,
            advisory=locked,
            previous_value={"state": State.DISMISSED.value},
            new_value={"state": target_state},
            metadata={
                "advisory_id": locked.advisory_id,
                "project_slug": locked.project.slug,
                "cve_request_restored": cve_request_restored,
                "orphan_disposition": orphan_disposition,
            },
        )
        record(
            action=Action.ADVISORY_STATE_CHANGED,
            actor=by,
            advisory=locked,
            previous_value={"state": State.DISMISSED},
            new_value={"state": target_state},
        )

        transaction.on_commit(partial(_enqueue_triage_notification, locked.pk, "advisory_reopened"))

    return locked


def reassign_triage_project(advisory: Advisory, *, by, new_project, note: str = "") -> Advisory:
    """Change a triage advisory's project without promoting it.

    Admin: any project (incl. the ``unsorted`` sentinel). Team member:
    only between projects they're on. Triage state is preserved so the
    receiving team picks it up. Clears the admin-routing flag iff ``by``
    is an admin (matching the legacy intake.services.reassign_project
    semantics).
    """
    clean_note = (note or "").strip()

    with transaction.atomic():
        locked = Advisory.objects.select_for_update().get(pk=advisory.pk)
        if locked.state != State.TRIAGE:
            raise ValueError(f"Advisory is not in triage state (currently {locked.state}).")

        admin = is_global_admin(by)
        if not admin:
            if not can_triage(by, locked):
                raise PermissionDenied("You may not act on this advisory.")
            if not is_security_team_member(by, new_project):
                raise PermissionDenied("You are not on the target project's security team.")

        previous_project = locked.project
        if previous_project == new_project:
            raise ValueError("Target project is the same as the current project.")

        locked.project = new_project
        locked.save(update_fields=["project", "modified_at"])
        # project_slug is payload-visible, so a reassignment is an edit.
        record_advisory_version(locked, editor=by, if_changed=True)

        intake = getattr(locked, "intake", None)
        cleared_flag = False
        if admin and intake is not None and intake.needs_admin_routing:
            _clear_routing_flag(intake)
            cleared_flag = True

        record(
            action=Action.ADVISORY_PROJECT_CHANGED,
            actor=by,
            advisory=locked,
            previous_value={"project_slug": previous_project.slug},
            new_value={"project_slug": new_project.slug},
            metadata={
                "advisory_id": locked.advisory_id,
                "note": clean_note,
                "cleared_flag": cleared_flag,
                "in_triage": True,
            },
        )

        transaction.on_commit(
            partial(_enqueue_triage_notification, locked.pk, "advisory_triage_reassigned")
        )

    return locked


def flag_for_admin_routing(advisory: Advisory, *, by, note: str) -> Advisory:
    """Tag a misrouted triage advisory for admin review.

    Locks out non-admin triagers (via ``can_triage``) until an admin
    re-routes (or dismisses/promotes) it. A non-empty ``note`` is required
    — the whole point of the flag is to tell admins where it should go.
    """
    clean_note = (note or "").strip()
    if not clean_note:
        raise ValueError("A routing note is required.")

    with transaction.atomic():
        locked = Advisory.objects.select_for_update().get(pk=advisory.pk)
        if not can_flag_for_admin_routing(by, locked):
            raise PermissionDenied("You may not flag this advisory.")
        if locked.state != State.TRIAGE:
            raise ValueError(f"Advisory is not in triage state (currently {locked.state}).")

        intake, _created = AdvisoryIntakeMetadata.objects.get_or_create(advisory=locked)
        if intake.needs_admin_routing:
            raise ValueError("Advisory is already flagged for admin routing.")

        intake.needs_admin_routing = True
        intake.admin_routing_note = clean_note
        intake.flagged_for_routing_at = timezone.now()
        intake.flagged_for_routing_by = by
        intake.save(
            update_fields=[
                "needs_admin_routing",
                "admin_routing_note",
                "flagged_for_routing_at",
                "flagged_for_routing_by",
            ]
        )

        record(
            action=Action.ADVISORY_FLAGGED_FOR_ROUTING,
            actor=by,
            advisory=locked,
            metadata={
                "advisory_id": locked.advisory_id,
                "project_slug": locked.project.slug,
                "note": clean_note,
            },
        )

        transaction.on_commit(
            partial(_enqueue_triage_notification, locked.pk, "advisory_flagged_for_routing")
        )

    return locked


def clear_admin_routing_flag(advisory: Advisory, *, by, note: str = "") -> Advisory:
    """Clear the admin-routing flag on a triage advisory.

    Reverses :func:`flag_for_admin_routing`: hands a flagged triage advisory
    back to its project's triagers. The note is optional — the stored
    sidecar note is wiped, the caller-supplied note is recorded only in
    the audit metadata for context.
    """
    clean_note = (note or "").strip()

    with transaction.atomic():
        locked = Advisory.objects.select_for_update().get(pk=advisory.pk)
        if not can_clear_admin_routing_flag(by, locked):
            raise PermissionDenied("You may not clear the flag on this advisory.")
        if locked.state != State.TRIAGE:
            raise ValueError(f"Advisory is not in triage state (currently {locked.state}).")
        intake = getattr(locked, "intake", None)
        if intake is None or not intake.needs_admin_routing:
            raise ValueError("Advisory is not flagged for admin routing.")

        previous_note = intake.admin_routing_note
        _clear_routing_flag(intake)

        record(
            action=Action.ADVISORY_ROUTING_FLAG_CLEARED,
            actor=by,
            advisory=locked,
            metadata={
                "advisory_id": locked.advisory_id,
                "project_slug": locked.project.slug,
                "previous_note": previous_note,
                "note": clean_note,
            },
        )

        transaction.on_commit(
            partial(_enqueue_triage_notification, locked.pk, "advisory_routing_flag_cleared")
        )

    return locked


# ---- Version history -------------------------------------------------------


@transaction.atomic
def record_advisory_version(
    advisory: Advisory,
    *,
    editor,
    if_changed: bool = False,
) -> AdvisoryVersion | None:
    """Append the next ``AdvisoryVersion`` for ``advisory``.

    Mirrors the ``add_comment`` / ``edit_comment`` write helpers in
    :mod:`comments.services`. Takes a row lock on the advisory so two
    concurrent edits can't race to compute the same next version number.

    ``editor`` is normalised to ``None`` for anonymous or unauthenticated
    actors (matching the legacy ``Advisory.take_snapshot`` semantics) and
    for system-driven callers (e.g. GHSA sync).

    Pass ``if_changed=True`` to skip the append when the latest payload is
    identical to the live ``Advisory.to_payload()`` — useful for callers
    that fire on every sync tick but only want a row when content
    actually moved. Returns ``None`` in that case.
    """
    new_payload = advisory.to_payload()
    Advisory.objects.select_for_update().filter(pk=advisory.pk).first()
    latest = AdvisoryVersion.objects.filter(advisory=advisory).order_by("-version").first()
    if if_changed and latest is not None and latest.payload == new_payload:
        return None
    next_version = (latest.version + 1) if latest is not None else 1
    return AdvisoryVersion.objects.create(
        advisory=advisory,
        version=next_version,
        payload=new_payload,
        editor=actor_or_none(editor),
    )


def history_for_advisory(advisory: Advisory, *, viewer) -> list[AdvisoryVersion]:
    """Return the ordered version history visible to ``viewer``.

    Re-checks view permission — the endpoint is reachable by URL, so we
    don't trust the caller to have already gated access. Mirrors
    :func:`comments.services.history_for_comment`.
    """
    if not can_view(viewer, advisory):
        raise PermissionDenied("You do not have access to this advisory.")
    return list(
        AdvisoryVersion.objects.filter(advisory=advisory)
        .select_related("editor")
        .prefetch_related("editor__groups")
        .order_by("version")
    )


def latest_version(advisory: Advisory) -> AdvisoryVersion | None:
    """Return the most recent ``AdvisoryVersion`` for ``advisory``, or ``None``.

    Used by review / publication workflows to pin a task to the content
    that's current at the moment the workflow starts.
    """
    return AdvisoryVersion.objects.filter(advisory=advisory).order_by("-version").first()


def changed_payload_fields(old: dict | None, new: dict) -> list[str]:
    """Sorted list of top-level keys that differ between two ``to_payload`` dicts.

    Returns ``[]`` when ``old`` is falsy (no prior payload — i.e. the
    advisory was just created and no second snapshot exists yet). Callers
    pass the result into ``ADVISORY_EDITED``'s ``metadata.changed_fields``
    so the timeline can render which fields actually moved.
    """
    if not old:
        return []
    return sorted(k for k in new if new.get(k) != old.get(k))


DETAILS_HISTORY_PAGE_SIZE = 10


def details_history(
    advisory: Advisory,
    *,
    viewer,
    page_size: int = DETAILS_HISTORY_PAGE_SIZE,
    before_version_id: int | None = None,
) -> dict:
    """Return one page of the description's edit history.

    Walks the full version history oldest→newest and *keeps* only those
    versions whose ``payload['details']`` differs from the previous kept
    version's. The newest-first kept list is then sliced by the cursor:

    * ``before_version_id=None`` returns the first page (most recent
      ``page_size`` entries).
    * ``before_version_id=<pk>`` drops everything up to **and
      including** that pk in the newest-first order and returns the
      next ``page_size`` entries.

    Diffs (``text_diff``) are computed *only* for the slice we return,
    not for every kept version, so paging through a 100-edit advisory
    only diffs the visible 10 cards per request.

    Returned shape::

        {"entries":     [{"version": ..., "diff_chunks": ...,
                          "is_initial": bool, "full_markdown": str}, ...],
         "next_cursor": int | None,
         "total_kept":  int}

    Permission gating is delegated to :func:`history_for_advisory`.
    """
    from common.text_diff import text_diff

    versions = history_for_advisory(advisory, viewer=viewer)

    # Walk chronologically once to identify "kept" versions + their bodies.
    # No diffs yet — only the slice gets diffed below.
    kept: list[tuple[AdvisoryVersion, str, str | None, bool]] = []
    # (version, this_details, prev_kept_details_or_None, is_initial)
    prev_details: str | None = None
    for version in versions:
        details = (version.payload or {}).get("details", "") or ""
        if prev_details is None:
            kept.append((version, details, None, True))
            prev_details = details
            continue
        if details == prev_details:
            continue
        kept.append((version, details, prev_details, False))
        prev_details = details

    # Newest-first display order.
    kept.reverse()
    total_kept = len(kept)

    # Apply the cursor.
    start = 0
    if before_version_id is not None:
        for idx, (version, _details, _prev, _initial) in enumerate(kept):
            if version.pk == before_version_id:
                start = idx + 1
                break
        else:
            # Unknown cursor → return empty page rather than the whole list,
            # so a malformed link doesn't dump everything in one shot.
            return {"entries": [], "next_cursor": None, "total_kept": total_kept}

    slice_end = start + page_size
    slice_ = kept[start:slice_end]

    entries: list[dict] = []
    for version, details, prev_kept_details, is_initial in slice_:
        entries.append(
            {
                "version": version,
                "diff_chunks": [] if is_initial else text_diff(prev_kept_details or "", details),
                "is_initial": is_initial,
                "full_markdown": details,
            }
        )

    next_cursor = entries[-1]["version"].pk if entries and slice_end < total_kept else None
    return {"entries": entries, "next_cursor": next_cursor, "total_kept": total_kept}


# ---- helpers ---------------------------------------------------------------

_ROUTING_FLAG_FIELDS = [
    "needs_admin_routing",
    "admin_routing_note",
    "flagged_for_routing_at",
    "flagged_for_routing_by",
]


def _clear_routing_flag(intake) -> None:
    """Reset the admin-routing sidecar fields and persist them."""
    intake.needs_admin_routing = False
    intake.admin_routing_note = ""
    intake.flagged_for_routing_at = None
    intake.flagged_for_routing_by = None
    intake.save(update_fields=_ROUTING_FLAG_FIELDS)


def _enqueue_triage_notification(advisory_pk: int, event: str) -> None:
    """Deferred import: notifications.tasks may import models, avoid cycles."""
    from notifications.tasks import send_advisory_triage_event_email

    safe_enqueue(send_advisory_triage_event_email, advisory_pk, event)


def queue_advisory_created_notification(advisory_pk: int) -> None:
    """Enqueue the ``advisory_created`` notification for ``advisory_pk``.

    Fired on first create, on a human project reassignment, and on a
    PMI-driven re-home (``ghsa.services.sync_project_repos_from_pmi``).
    Recipients are resolved at send time (the advisory's *current* project
    security team), so a broker outage here is not load-bearing — workers
    re-read the project. Deferred import avoids a notifications↔models cycle.
    """
    from notifications.tasks import send_advisory_event_email

    safe_enqueue(send_advisory_event_email, advisory_pk, "advisory_created")
