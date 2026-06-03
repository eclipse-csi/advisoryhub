"""HTML views for advisory authoring.

Every view enforces authorization via :mod:`advisories.permissions`.
Templates only *display* using these helpers; they never decide.
"""

from __future__ import annotations

import uuid
from functools import partial
from typing import cast

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Q
from django.forms import ModelChoiceField
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from audit.models import Action
from audit.services import record_from_request
from common.enqueue import safe_enqueue
from common.ratelimit import html_ratelimit
from projects.models import Project

from . import permissions as perms
from . import services
from .diff import live_vs_version, version_diff
from .form_assembly import (
    advanced_form_context,
    apply_json_fields,
    attach_validation_errors,
    build_event_formsets,
    build_formsets,
    validate_all,
)
from .forms import (
    AdvisoryDismissForm,
    AdvisoryForm,
    GhsaLinkedAdvisoryEditForm,
)
from .models import Advisory, AdvisoryVersion, Kind, ReviewStatus, State
from .permissions import UNSORTED_PROJECT_SLUG

# ---------------------------------------------------------------------------
# Listing & detail
# ---------------------------------------------------------------------------


@login_required
def advisory_list(request):
    """List advisories the current user can see.

    Supported query params (all optional):
      ``q``                full-text on summary/details/advisory_id/aliases
      ``project``          project UUID
      ``state``            draft|published|dismissed
      ``review_status``    none|submitted|changes_requested|approved|rejected
      ``republish_required`` "1" → only advisories with the flag set
    """
    user = request.user
    qs = perms.visible_advisories(user)

    qs, applied = _apply_advisory_filters(qs, request)
    qs = qs.select_related("project").order_by("-modified_at")

    # Cap the page at a reasonable size so a careless filter doesn't
    # render a million rows. Use the same param name as the API.
    try:
        page_size = min(200, max(1, int(request.GET.get("page_size", "50"))))
        page = max(1, int(request.GET.get("page", "1")))
    except (TypeError, ValueError):
        page, page_size = 1, 50
    total = qs.count()
    offset = (page - 1) * page_size
    advisories = list(qs[offset : offset + page_size])

    return render(
        request,
        "advisories/list.html",
        {
            "advisories": advisories,
            "filters": applied,
            "projects_for_filter": _projects_for_filter(user),
            "total": total,
            "page": page,
            "page_size": page_size,
            "num_pages": max(1, (total + page_size - 1) // page_size),
            "has_next": offset + page_size < total,
            "has_prev": page > 1,
        },
    )


def _apply_advisory_filters(qs, request):
    """Translate ?q/?project/?state/?review_status/?republish_required into a queryset.

    Returns (filtered_qs, applied_filters_dict) — the latter is a flat
    dict the template uses to repopulate the filter form.
    """
    applied: dict[str, str] = {}
    q = (request.GET.get("q") or "").strip()
    if q:
        applied["q"] = q
        qs = qs.filter(
            Q(summary__icontains=q)
            | Q(details__icontains=q)
            | Q(advisory_id__icontains=q)
            | Q(aliases__icontains=q)
        )
    project = (request.GET.get("project") or "").strip()
    if project:
        try:
            project_uuid = uuid.UUID(project)
        except ValueError:
            project_uuid = None
        if project_uuid is not None:
            applied["project"] = project
            qs = qs.filter(project_id=project_uuid)
    state = (request.GET.get("state") or "").strip()
    if state and state in dict(State.choices):
        applied["state"] = state
        qs = qs.filter(state=state)
    review_status = (request.GET.get("review_status") or "").strip()
    if review_status:
        applied["review_status"] = review_status
        qs = qs.filter(review_status=review_status)
    if request.GET.get("republish_required") == "1":
        applied["republish_required"] = "1"
        qs = qs.filter(republish_required=True)
    return qs, applied


def _projects_for_filter(user):
    """The set of projects the user can plausibly filter by.

    Admins see every project; everyone else sees the projects they're on
    the security team of, plus any project they have a grant on
    (best-effort — if access isn't installed, falls back to team only).
    """
    if perms.is_global_admin(user):
        return Project.objects.order_by("name")
    return Project.objects.filter(security_team__in=user.groups.all()).distinct().order_by("name")


@login_required
@require_http_methods(["GET"])
def advisory_detail(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_view(request.user, advisory):
        raise PermissionDenied("You don't have access to this advisory.")
    record_from_request(request, action=Action.ADVISORY_VIEWED, advisory=advisory)
    last_publication_task = None
    try:
        last_publication_task = advisory.publication_tasks.prefetch_related("artifacts").first()
    except Exception:
        pass

    is_triage = advisory.state == State.TRIAGE
    intake = getattr(advisory, "intake", None) if is_triage else None
    # Count of description edits, for the "history · N edits" trigger next to
    # <h2>Details</h2>. Reuses the same filtering as the drawer so the count
    # and the drawer content never diverge. Subtract 1 for the initial v1.
    # Use ``page_size=0`` to avoid computing diffs we don't need here.
    details_edit_count = max(
        services.details_history(advisory, viewer=request.user, page_size=0)["total_kept"] - 1,
        0,
    )

    # @-mention completion payload — only built for users who can comment (the
    # menu reveals the advisory's roster, which a commenter can already see).
    from comments.services import mention_candidates as _mention_candidates

    mention_candidates = (
        _mention_candidates(advisory) if perms.can_comment(request.user, advisory) else []
    )

    return render(
        request,
        "advisories/detail.html",
        {
            "advisory": advisory,
            "mention_candidates": mention_candidates,
            "can_edit": perms.can_edit(request.user, advisory),
            "can_dismiss": perms.can_dismiss(request.user, advisory),
            "can_reopen": perms.can_reopen(request.user, advisory),
            "can_publish": perms.can_publish(request.user, advisory),
            "can_grant": perms.can_grant_access(request.user, advisory),
            "can_request_cve": perms.can_request_cve(request.user, advisory),
            "can_unassign_cve": perms.can_unassign_cve(request.user, advisory),
            "cve_request_state": _cve_request_state(request.user, advisory),
            "can_submit_for_review": perms.can_submit_for_review(request.user, advisory),
            "can_withdraw_review": perms.can_withdraw_review(request.user, advisory),
            "can_revoke_approval": perms.can_revoke_approval(request.user, advisory),
            "can_review": perms.can_review(request.user),
            "open_review_task": advisory.review_tasks.filter(status="open").first()
            if hasattr(advisory, "review_tasks")
            else None,
            "last_publication_task": last_publication_task,
            "is_ghsa_linked": advisory.kind == Kind.GHSA_LINKED,
            "can_sync_ghsa": perms.can_sync_ghsa(request.user, advisory),
            "is_triage": is_triage,
            "intake": intake,
            "can_triage": is_triage and perms.can_triage(request.user, advisory),
            "can_flag_routing": is_triage
            and perms.can_flag_for_admin_routing(request.user, advisory),
            "can_clear_routing": is_triage
            and intake is not None
            and intake.needs_admin_routing
            and perms.can_clear_admin_routing_flag(request.user, advisory),
            "is_unsorted": is_triage and advisory.project.slug == UNSORTED_PROJECT_SLUG,
            "details_edit_count": details_edit_count,
            **_lifecycle_hints(advisory, last_publication_task=last_publication_task),
        },
    )


def _cve_request_state(user, advisory: Advisory) -> str:
    """Return one of: ``available``, ``pending``, ``banned``, ``assigned``,
    ``not_allowed`` — drives the per-state UI on the advisory detail page.

    The four explicit states are surfaced separately (rather than collapsed
    into a single ``can_request_cve`` flag) so the template can render the
    matching label/badge without re-querying.
    """
    from workflows.models import CveRequestStatus

    if not perms.can_edit(user, advisory):
        return "not_allowed"
    if advisory.assigned_cve_id:
        return "assigned"
    if advisory.cve_requests_banned:
        return "banned"
    if advisory.cve_requests.filter(status=CveRequestStatus.QUEUED).exists():
        return "pending"
    # Requesting a CVE is owner-only (see permissions.can_request_cve). A
    # collaborator may edit the advisory but must not initiate the request,
    # so they get no actionable button even when no blocking state applies.
    if not perms.can_request_cve(user, advisory):
        return "not_allowed"
    return "available"


def _lifecycle_hints(advisory: Advisory, *, last_publication_task) -> dict[str, str]:
    """Single-line, role-neutral hints surfaced in the three sidebar cards
    (Lifecycle, Review, Publication). Computed in the view — the template
    only displays.

    These intentionally don't repeat per-button help text; they answer
    "what is happening with this sub-machine?" at a glance.
    """
    state = advisory.state
    rs = advisory.review_status

    # Lifecycle ----------------------------------------------------------
    if state == State.TRIAGE:
        lifecycle = "Untrusted report. Promote to start the standard workflow, or dismiss."
    elif state == State.DRAFT:
        lifecycle = "Authoring in progress. Edits append a new version."
    elif state == State.PUBLISHED:
        if advisory.republish_required:
            lifecycle = "Live — but edits since last publish need re-publishing."
        else:
            lifecycle = "Live in the publication repo."
    elif state == State.DISMISSED:
        prior = advisory.dismissed_from_state or "earlier state"
        lifecycle = f"Dismissed from {prior}. Owners can reopen."
    else:
        lifecycle = ""

    # Review -------------------------------------------------------------
    if state == State.TRIAGE:
        review = "Review opens once the report is promoted to draft."
    elif state == State.DISMISSED:
        review = "Not applicable while dismissed."
    elif state == State.PUBLISHED and rs == ReviewStatus.NONE:
        review = "Past review — already published."
    elif rs == ReviewStatus.NONE:
        review = "Not submitted."
    elif rs == ReviewStatus.SUBMITTED:
        review = "Awaiting decision by the global security team."
    elif rs == ReviewStatus.APPROVED:
        review = "Approved — publication unlocked."
    elif rs == ReviewStatus.CHANGES_REQUESTED:
        review = "Reviewer asked for changes. Reopen, edit, then resubmit."
    else:
        review = ""

    # Publication --------------------------------------------------------
    if state == State.TRIAGE:
        publication = "Available once the report is promoted (and reviewed)."
    elif state == State.DISMISSED:
        publication = "Not applicable while dismissed."
    elif state == State.DRAFT:
        if rs == ReviewStatus.SUBMITTED:
            publication = "Blocked while the review is in progress."
        elif rs == ReviewStatus.APPROVED:
            publication = "Ready to publish."
        elif rs == ReviewStatus.CHANGES_REQUESTED:
            publication = "Reviewer asked for changes — fix them first."
        else:
            publication = "Publish when ready (review may be required)."
    elif state == State.PUBLISHED:
        if advisory.republish_required:
            publication = "Re-publish required to push recent edits."
        elif last_publication_task and last_publication_task.status == "failed":
            publication = "Last publication run failed — see details below."
        else:
            publication = "Live in the publication repo."
    else:
        publication = ""

    return {
        "lifecycle_hint": lifecycle,
        "review_hint": review,
        "publication_hint": publication,
    }


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["GET", "POST"])
def advisory_create(request):
    user = request.user
    creatable_projects = _projects_user_can_create_for(user)
    if not perms.is_global_admin(user) and not creatable_projects.exists():
        raise PermissionDenied("You are not on any project's security team.")

    if request.method == "POST":
        form = AdvisoryForm(request.POST)
        cast(ModelChoiceField, form.fields["project"]).queryset = creatable_projects
        formsets = build_formsets(request, None)
        event_formsets = build_event_formsets(request, formsets["affected"], None)
        if validate_all(form, formsets, event_formsets):
            advisory: Advisory = form.save(commit=False)
            if not perms.can_create_advisory_for_project(user, advisory.project):
                raise PermissionDenied("You cannot create an advisory for that project.")
            advisory.created_by = user
            apply_json_fields(advisory, formsets, event_formsets)
            if attach_validation_errors(form, advisory):
                # v1 is seeded by the advisories.signals post_save hook.
                advisory.save()
                record_from_request(
                    request,
                    action=Action.ADVISORY_CREATED,
                    advisory=advisory,
                    new_value={
                        "project": advisory.project.slug,
                        "advisory_id": advisory.advisory_id,
                    },
                )
                transaction.on_commit(partial(_queue_advisory_created, advisory.pk))
                return redirect("advisories:detail", advisory_id=advisory.advisory_id)
    else:
        form = AdvisoryForm()
        cast(ModelChoiceField, form.fields["project"]).queryset = creatable_projects
        formsets = build_formsets(request, None)
        event_formsets = build_event_formsets(request, formsets["affected"], None)

    return render(
        request,
        "advisories/form.html",
        {
            "form": form,
            "mode": "create",
            "advisory": None,
            **advanced_form_context(formsets, event_formsets),
        },
    )


# ---------------------------------------------------------------------------
# Edit
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["GET", "POST"])
def advisory_edit(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_edit(request.user, advisory):
        raise PermissionDenied("You cannot edit this advisory.")

    user = request.user
    # Combine via primary key set instead of `|` because
    # _projects_user_can_create_for returns a `.distinct()` queryset and
    # Django refuses to OR-combine distinct + non-distinct.
    own_pks = list(_projects_user_can_create_for(user).values_list("pk", flat=True))
    creatable_projects = Project.objects.filter(pk__in=set(own_pks + [advisory.project_id]))
    is_triage = advisory.state == State.TRIAGE

    # GHSA-linked advisories: OSV-shaped fields are read-only (synced from
    # the upstream GHSA on GitHub). Only project assignment is editable
    # here; the rest of the metadata flows through ghsa.services.
    if advisory.kind == Kind.GHSA_LINKED:
        return _advisory_edit_ghsa_linked(request, advisory, creatable_projects)

    if request.method == "POST":
        # Capture pre-edit state *before* binding the form: ModelForm._post_clean
        # mutates the bound instance during is_valid(), so reading these after
        # validate_all() would already reflect the submitted values.
        previous = {
            "summary": advisory.summary,
            "project": advisory.project.slug,
            "state": advisory.state,
        }
        previous_project_id = advisory.project_id
        # Snapshot the current payload so we can diff against it after save
        # and surface which payload fields the editor actually changed.
        prior_version = services.latest_version(advisory)
        prior_payload = prior_version.payload if prior_version else None

        form = AdvisoryForm(request.POST, instance=advisory)
        cast(ModelChoiceField, form.fields["project"]).queryset = creatable_projects
        formsets = build_formsets(request, advisory)
        event_formsets = build_event_formsets(request, formsets["affected"], advisory)
        if validate_all(form, formsets, event_formsets):
            new_project = form.cleaned_data["project"]
            project_changed = new_project.pk != previous_project_id
            if (
                project_changed
                and not is_triage
                and not perms.can_change_project(user, advisory, new_project)
            ):
                raise PermissionDenied("You cannot change the project to one you don't belong to.")
            # For TRIAGE rows, route the project change through the triage
            # service so we get the in-triage audit metadata + the
            # advisory_triage_reassigned notification (and the admin-flag
            # clearing) — the standard path is wrong for pre-draft work.
            if is_triage and project_changed:
                try:
                    services.reassign_triage_project(advisory, by=user, new_project=new_project)
                except (ValueError, PermissionDenied) as exc:
                    form.add_error("project", str(exc))
                    return render(
                        request,
                        "advisories/form.html",
                        {
                            "form": form,
                            "mode": "edit",
                            "advisory": advisory,
                            **advanced_form_context(formsets, event_formsets),
                        },
                    )
            updated: Advisory = form.save(commit=False)
            apply_json_fields(updated, formsets, event_formsets)
            if attach_validation_errors(form, updated):
                # If editing after publish, mark for re-publication
                if updated.state == State.PUBLISHED:
                    updated.republish_required = True
                # Any non-admin edit on an APPROVED advisory voids the
                # approval — what was approved no longer matches what
                # exists. Mature publishers retain publish capability via
                # the project-flag branch of can_publish; the badge just
                # stops claiming "Approved".
                invalidated_approval = (
                    updated.review_status == ReviewStatus.APPROVED
                    and not perms.is_global_admin(request.user)
                )
                if invalidated_approval:
                    updated.review_status = ReviewStatus.NONE
                # When the project actually changed on a non-triage row,
                # prompt writers to review who still needs access — the old
                # project's security team silently loses implicit write, and
                # the new team gains it. Skipped in TRIAGE: no grants exist
                # to audit pre-draft.
                if project_changed and not is_triage:
                    updated.access_review_required_at = timezone.now()
                updated.save()
                new_version = services.record_advisory_version(updated, editor=user)
                new_value = {
                    "summary": updated.summary,
                    "project": updated.project.slug,
                    "state": updated.state,
                    "version": new_version.version if new_version else None,
                }
                changed_fields = services.changed_payload_fields(
                    prior_payload, updated.to_payload()
                )
                record_from_request(
                    request,
                    action=Action.ADVISORY_EDITED,
                    advisory=updated,
                    previous_value=previous,
                    new_value=new_value,
                    metadata={"changed_fields": changed_fields},
                )
                if invalidated_approval:
                    record_from_request(
                        request,
                        action=Action.ADVISORY_REVIEW_APPROVAL_INVALIDATED,
                        advisory=updated,
                        previous_value={"review_status": ReviewStatus.APPROVED},
                        new_value={"review_status": ReviewStatus.NONE},
                    )
                if previous["project"] != new_value["project"] and not is_triage:
                    # Triage already emitted PROJECT_CHANGED + the triage
                    # notification via reassign_triage_project; skip the
                    # standard advisory_created path here.
                    record_from_request(
                        request,
                        action=Action.ADVISORY_PROJECT_CHANGED,
                        advisory=updated,
                        previous_value=previous["project"],
                        new_value=new_value["project"],
                    )
                    transaction.on_commit(partial(_queue_advisory_created, updated.pk))
                return redirect("advisories:detail", advisory_id=updated.advisory_id)
    else:
        form = AdvisoryForm(instance=advisory)
        cast(ModelChoiceField, form.fields["project"]).queryset = creatable_projects
        formsets = build_formsets(request, advisory)
        event_formsets = build_event_formsets(request, formsets["affected"], advisory)

    return render(
        request,
        "advisories/form.html",
        {
            "form": form,
            "mode": "edit",
            "advisory": advisory,
            **advanced_form_context(formsets, event_formsets),
        },
    )


def _advisory_edit_ghsa_linked(request, advisory, creatable_projects):
    """Edit path for GHSA-linked advisories: only ``project`` is editable.

    The OSV-shaped fields are rendered as a read-only panel on the same
    template; everything else flows through the GHSA sync workflow.
    """
    previous_project_id = advisory.project_id
    previous = {"project": advisory.project.slug}
    prior_version = services.latest_version(advisory)
    prior_payload = prior_version.payload if prior_version else None
    if request.method == "POST":
        form = GhsaLinkedAdvisoryEditForm(request.POST, instance=advisory)
        cast(ModelChoiceField, form.fields["project"]).queryset = creatable_projects
        if form.is_valid():
            new_project = form.cleaned_data["project"]
            project_changed = new_project.pk != previous_project_id
            if project_changed and not perms.can_change_project(
                request.user, advisory, new_project
            ):
                raise PermissionDenied("You cannot change the project to one you don't belong to.")
            updated = form.save(commit=False)
            if updated.state == State.PUBLISHED:
                updated.republish_required = True
            invalidated_approval = (
                updated.review_status == ReviewStatus.APPROVED
                and not perms.is_global_admin(request.user)
            )
            if invalidated_approval:
                updated.review_status = ReviewStatus.NONE
            if project_changed:
                updated.access_review_required_at = timezone.now()
            updated.save(
                update_fields=[
                    "project",
                    "republish_required",
                    "review_status",
                    "access_review_required_at",
                    "modified_at",
                ]
            )
            new_version = services.record_advisory_version(
                updated, editor=request.user, if_changed=True
            )
            new_value = {
                "project": updated.project.slug,
                "version": new_version.version if new_version else None,
            }
            changed_fields = services.changed_payload_fields(prior_payload, updated.to_payload())
            record_from_request(
                request,
                action=Action.ADVISORY_EDITED,
                advisory=updated,
                previous_value=previous,
                new_value=new_value,
                metadata={"changed_fields": changed_fields},
            )
            if invalidated_approval:
                record_from_request(
                    request,
                    action=Action.ADVISORY_REVIEW_APPROVAL_INVALIDATED,
                    advisory=updated,
                    previous_value={"review_status": ReviewStatus.APPROVED},
                    new_value={"review_status": ReviewStatus.NONE},
                )
            if previous["project"] != new_value["project"]:
                record_from_request(
                    request,
                    action=Action.ADVISORY_PROJECT_CHANGED,
                    advisory=updated,
                    previous_value=previous["project"],
                    new_value=new_value["project"],
                )
            return redirect("advisories:detail", advisory_id=updated.advisory_id)
    else:
        form = GhsaLinkedAdvisoryEditForm(instance=advisory)
        cast(ModelChoiceField, form.fields["project"]).queryset = creatable_projects
    return render(
        request,
        "advisories/form_ghsa_linked.html",
        {
            "form": form,
            "advisory": advisory,
            "mode": "edit",
            "is_ghsa_linked": True,
        },
    )


# ---------------------------------------------------------------------------
# Dismiss
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["GET", "POST"])
def advisory_dismiss(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    # Triage rows have a stricter dismissal gate (flagged-for-routing locks
    # out non-admin team members) — defer to can_triage there. For all
    # other states fall through to the standard can_dismiss check.
    if advisory.state == State.TRIAGE:
        if not perms.can_triage(request.user, advisory):
            raise PermissionDenied("You cannot dismiss this advisory.")
    elif not perms.can_dismiss(request.user, advisory):
        if advisory.state == State.PUBLISHED:
            raise PermissionDenied("Published advisories cannot be dismissed.")
        if advisory.assigned_cve_id and not perms.is_global_admin(request.user):
            raise PermissionDenied(
                "This advisory has an assigned CVE. Ask an admin to remove the CVE "
                "assignment first, or to dismiss the advisory themselves."
            )
        raise PermissionDenied("You cannot dismiss this advisory.")

    if request.method == "POST":
        form = AdvisoryDismissForm(request.POST)
        if form.is_valid():
            reason = form.cleaned_data["reason"]
            # Triage dismissals route through the triage service for the
            # correct state-change audit + advisory_triage_dismissed
            # notification.
            if advisory.state == State.TRIAGE:
                try:
                    services.dismiss_triage(advisory, by=request.user, reason=reason)
                except ValueError as exc:
                    form.add_error("reason", str(exc))
                    return render(
                        request, "advisories/dismiss.html", {"form": form, "advisory": advisory}
                    )
                return redirect("advisories:detail", advisory_id=advisory.advisory_id)

            from workflows.services import (
                cancel_open_cve_request,
                cancel_pending_review,
                unassign_cve,
            )

            with transaction.atomic():
                previous_state = advisory.state
                advisory.state = State.DISMISSED
                advisory.dismissed_reason = reason
                advisory.dismissed_from_state = previous_state
                advisory.save()
                record_from_request(
                    request,
                    action=Action.ADVISORY_DISMISSED,
                    advisory=advisory,
                    previous_value=previous_state,
                    new_value=State.DISMISSED,
                )
                # An open CVE request on a now-dismissed advisory is dead
                # work — auto-cancel it so the admin queue doesn't carry
                # the row.
                cancel_open_cve_request(
                    advisory,
                    by=request.user,
                    reason=f"Advisory dismissed: {reason}",
                )
                # Tear down any pending review state so a later reopen
                # lands in a clean draft (no stale CHANGES_REQUESTED
                # badge, no orphan OPEN ReviewTask on the admin queue, no
                # surviving APPROVED that would bypass review on the way
                # back out).
                cancel_pending_review(
                    advisory,
                    by=request.user,
                    reason=f"Advisory dismissed: {reason}",
                )
                # If a CVE was reserved for this advisory, it becomes an
                # orphan — the security team still needs to mark it rejected
                # at cve.org. ``can_dismiss`` guarantees the actor is an admin
                # when ``assigned_cve_id`` is set, so the admin-gated
                # ``unassign_cve`` will not raise PermissionDenied here.
                if advisory.assigned_cve_id:
                    unassign_cve(
                        advisory,
                        by=request.user,
                        reason=f"Advisory dismissed: {reason}",
                    )
            return redirect("advisories:detail", advisory_id=advisory.advisory_id)
    else:
        form = AdvisoryDismissForm()
    return render(request, "advisories/dismiss.html", {"form": form, "advisory": advisory})


# ---------------------------------------------------------------------------
# Reopen (dismissed → prior non-terminal state)
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["POST"])
def advisory_reopen(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_reopen(request.user, advisory):
        raise PermissionDenied("You cannot reopen this advisory.")
    try:
        services.reopen_advisory(advisory, by=request.user)
    except ValueError as exc:
        # The service raises ValueError only when the advisory is no longer
        # in DISMISSED state — surface as a 400 rather than crashing.
        raise PermissionDenied(str(exc)) from exc
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


# ---------------------------------------------------------------------------
# Access-review banner dismissal
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["POST"])
def advisory_access_review_dismiss(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_grant_access(request.user, advisory):
        raise PermissionDenied("You cannot dismiss the access-review banner.")
    if advisory.access_review_required_at is not None:
        previous = advisory.access_review_required_at
        advisory.access_review_required_at = None
        advisory.save(update_fields=["access_review_required_at"])
        record_from_request(
            request,
            action=Action.ADVISORY_ACCESS_REVIEW_DISMISSED,
            advisory=advisory,
            previous_value={"access_review_required_at": previous.isoformat()},
        )
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _queue_advisory_created(advisory_pk: int) -> None:
    """Enqueue the ``advisory_created`` notification.

    Fired on first create and on project reassignment. Recipients are
    resolved at send time (project security team only), so a broker
    outage here is not load-bearing — workers re-read the project.
    """
    from notifications.tasks import send_advisory_event_email

    safe_enqueue(send_advisory_event_email, advisory_pk, "advisory_created")


def _projects_user_can_create_for(user):
    if perms.is_global_admin(user):
        return Project.objects.all()
    return Project.objects.filter(security_team__in=user.groups.all()).distinct()


# ---------------------------------------------------------------------------
# Triage actions
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="20/h")
def advisory_promote(request, advisory_id: str):
    """Promote a triage advisory to draft.

    Accepts an optional ``project_slug`` to route an unrouted submission
    (or re-route a normal one as part of promotion). Authorization is
    re-checked inside the service.
    """
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if advisory.state != State.TRIAGE:
        raise PermissionDenied("This advisory is not in triage.")
    if not perms.can_triage(request.user, advisory):
        raise PermissionDenied("You may not triage this advisory.")

    raw_slug = (request.POST.get("project_slug") or "").strip()
    target_project = None
    if raw_slug:
        try:
            target_project = Project.objects.get(slug=raw_slug)
        except Project.DoesNotExist:
            return _detail_with_error(request, advisory, f"Unknown project {raw_slug!r}.")

    try:
        services.promote_triage_to_draft(advisory, by=request.user, project=target_project)
    except ValueError as exc:
        return _detail_with_error(request, advisory, str(exc))
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="20/h")
def advisory_flag(request, advisory_id: str):
    """Flag a triage advisory for admin re-routing.

    Always renders inside an HTMX modal; on success closes the modal and
    refreshes the page so the new banner appears.
    """
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if advisory.state != State.TRIAGE:
        raise PermissionDenied("This advisory is not in triage.")
    note = (request.POST.get("note") or "").strip()
    is_htmx = bool(getattr(request, "htmx", False))
    try:
        services.flag_for_admin_routing(advisory, by=request.user, note=note)
    except ValueError as exc:
        if is_htmx:
            return render(
                request,
                "advisories/_flag_modal.html",
                {"advisory": advisory, "error": str(exc)},
                status=400,
            )
        return _detail_with_error(request, advisory, str(exc))
    if is_htmx:
        from django.http import HttpResponse

        resp = HttpResponse(status=204)
        resp["HX-Refresh"] = "true"
        return resp
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["GET"])
def advisory_flag_modal(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if advisory.state != State.TRIAGE:
        raise Http404("Advisory is not in triage.")
    if not perms.can_flag_for_admin_routing(request.user, advisory):
        raise PermissionDenied("Flag is not available for this user/advisory.")
    return render(request, "advisories/_flag_modal.html", {"advisory": advisory})


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="20/h")
def advisory_clear_routing_flag(request, advisory_id: str):
    """Clear the admin-routing flag on a triage advisory."""
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if advisory.state != State.TRIAGE:
        raise PermissionDenied("This advisory is not in triage.")
    note = (request.POST.get("note") or "").strip()
    try:
        services.clear_admin_routing_flag(advisory, by=request.user, note=note)
    except ValueError as exc:
        return _detail_with_error(request, advisory, str(exc))
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


def _detail_with_error(request, advisory: Advisory, message: str):
    """Re-render the advisory detail with an inline error banner."""
    is_triage = advisory.state == State.TRIAGE
    intake = getattr(advisory, "intake", None) if is_triage else None
    return render(
        request,
        "advisories/detail.html",
        {
            "advisory": advisory,
            "can_edit": perms.can_edit(request.user, advisory),
            "can_dismiss": perms.can_dismiss(request.user, advisory),
            "can_reopen": perms.can_reopen(request.user, advisory),
            "can_publish": perms.can_publish(request.user, advisory),
            "can_grant": perms.can_grant_access(request.user, advisory),
            "can_request_cve": perms.can_request_cve(request.user, advisory),
            "can_unassign_cve": perms.can_unassign_cve(request.user, advisory),
            "cve_request_state": _cve_request_state(request.user, advisory),
            "can_submit_for_review": perms.can_submit_for_review(request.user, advisory),
            "can_withdraw_review": perms.can_withdraw_review(request.user, advisory),
            "can_revoke_approval": perms.can_revoke_approval(request.user, advisory),
            "can_review": perms.can_review(request.user),
            "open_review_task": None,
            "last_publication_task": None,
            "is_ghsa_linked": advisory.kind == Kind.GHSA_LINKED,
            "can_sync_ghsa": perms.can_sync_ghsa(request.user, advisory),
            "is_triage": is_triage,
            "intake": intake,
            "can_triage": is_triage and perms.can_triage(request.user, advisory),
            "can_flag_routing": is_triage
            and perms.can_flag_for_admin_routing(request.user, advisory),
            "can_clear_routing": is_triage
            and intake is not None
            and intake.needs_admin_routing
            and perms.can_clear_admin_routing_flag(request.user, advisory),
            "is_unsorted": is_triage and advisory.project.slug == UNSORTED_PROJECT_SLUG,
            "error": message,
        },
        status=400,
    )


# ---------------------------------------------------------------------------
# Version history + diff
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["GET"])
def advisory_history(request, advisory_id: str):
    """Legacy standalone edit-history page — now consolidated into the inline
    description-history drawer on the detail page (the "history · N edits"
    trigger by the Details heading). Redirect bookmarked/legacy links there,
    keeping the same view-permission gate so outsiders still get a 403 rather
    than a redirect that would leak the advisory's existence.
    """
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_view(request.user, advisory):
        raise PermissionDenied("You do not have access to this advisory.")
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["GET"])
def advisory_details_history(request, advisory_id: str):
    """Render the description (``details``) edit-history drawer.

    HTMX endpoint. The initial GET (no ``?before``) returns the full
    ``<dialog>`` shell with the first page of entries inside; a
    cursor'd GET returns just the list-fragment partial so HTMX can
    append the next page in place. Permission gating happens inside
    :func:`services.details_history` (raises ``PermissionDenied``).
    """
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)

    before_raw = request.GET.get("before")
    try:
        before_id = int(before_raw) if before_raw else None
    except ValueError:
        before_id = None

    page = services.details_history(advisory, viewer=request.user, before_version_id=before_id)
    template = (
        "common/_history_page.html" if before_id is not None else "advisories/_details_history.html"
    )
    return render(
        request,
        template,
        {
            "advisory": advisory,
            "entries": page["entries"],
            "next_cursor": page["next_cursor"],
            "load_more_url": reverse("advisories:details_history", args=[advisory.advisory_id]),
            "is_first_page": before_id is None,
        },
    )


@login_required
@require_http_methods(["GET"])
def advisory_version_diff(request, advisory_id: str, version_id: int):
    """Render the version-diff drawer for one version of an advisory.

    HTMX endpoint. The initial GET returns the ``<dialog>`` drawer shell;
    a ``?fragment=1`` GET returns just the body partial so the in-drawer
    "compare against" switcher can swap in place. A non-HTMX hit has no
    standalone page and redirects to the advisory detail.

    Default comparison is against the *current live* advisory — what's
    changed since this version was recorded. Pass ``?against=<other_version_id>``
    to compare two specific versions (e.g. the previous version vs. this one).
    """
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_view(request.user, advisory):
        raise PermissionDenied("You do not have access to this advisory.")
    version = get_object_or_404(AdvisoryVersion, pk=version_id, advisory=advisory)

    against_pk = request.GET.get("against")
    if against_pk:
        against = get_object_or_404(AdvisoryVersion, pk=against_pk, advisory=advisory)
        diff = version_diff(against, version)
        comparison_label = f"v{against.version}"
    else:
        against = None
        diff = live_vs_version(advisory, version)
        comparison_label = "current live record"

    # The diff is an in-page drawer (advisoryhub-dialogs.js), reached only via
    # HTMX from the detail/sidebar triggers. A direct (non-HTMX) hit on the URL
    # has no standalone page to render — send it back to the advisory.
    if not getattr(request, "htmx", False):
        return redirect("advisories:detail", advisory_id=advisory.advisory_id)

    template = (
        "advisories/_version_diff_body.html"
        if request.GET.get("fragment")
        else "advisories/_version_diff.html"
    )
    return render(
        request,
        template,
        {
            "advisory": advisory,
            "version": version,
            "against": against,
            "diff": diff,
            "comparison_label": comparison_label,
            "versions": list(advisory.versions.order_by("-version")[:10]),
        },
    )
