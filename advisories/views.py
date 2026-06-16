"""HTML views for advisory authoring.

Every view enforces authorization via :mod:`advisories.permissions`.
Templates only *display* using these helpers; they never decide.
"""

from __future__ import annotations

import uuid
from functools import partial
from typing import cast

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Case, Count, IntegerField, Q, Value, When
from django.forms import ModelChoiceField
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from audit.models import Action
from audit.services import record_from_request
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
)
from .models import Advisory, AdvisoryVersion, AdvisoryVisit, Kind, ReviewStatus, State
from .permissions import UNSORTED_PROJECT_SLUG
from .visit_markers import annotate_visit_markers, set_visit_markers

# ---------------------------------------------------------------------------
# Listing & detail
# ---------------------------------------------------------------------------

# Column sorting for the advisory list table. Logical keys (decoupled from DB
# column names, validated against this allowlist — mirrors how ``state`` is
# checked against State.choices) map to an ORM ordering and the column's natural
# first-click direction. An unknown/empty ``?sort`` falls back to _DEFAULT_SORT.
_SORT_COLUMNS = {
    "id": {"order": "advisory_id", "default_desc": False},
    "project": {"order": "project__name", "default_desc": False},
    "state": {"order": "__state_rank__", "default_desc": False},
    "review": {"order": "review_status", "default_desc": False},
    "modified": {"order": "modified_at", "default_desc": True},
}
_DEFAULT_SORT = "-modified"  # preserves the historical order_by("-modified_at")
# Lifecycle rank from State.choices declaration order (triage < draft <
# published < dismissed) so "ascending State" reads as workflow progression and
# a future 5th state slots in automatically.
_STATE_RANK = {value: i for i, (value, _label) in enumerate(State.choices)}


def _parse_sort(raw: str) -> tuple[str, bool]:
    """Resolve a raw ``?sort`` value to ``(logical_key, descending)``.

    A leading ``-`` means descending. Unknown or empty keys fall back to the
    default sort, mirroring the invalid-state handling in ``advisory_list``.
    """
    desc = raw.startswith("-")
    key = raw[1:] if desc else raw
    if key not in _SORT_COLUMNS:
        key = _DEFAULT_SORT.lstrip("-")
        desc = _DEFAULT_SORT.startswith("-")
    return key, desc


def _sort_order_by(key: str, desc: bool) -> tuple[list[str], dict]:
    """``order_by`` terms + annotations for a validated ``(key, desc)``.

    Appends ``pk`` as a unique, stable final tiebreaker so the low-cardinality
    state/review sorts paginate deterministically across LIMIT/OFFSET windows.
    The state sort orders by a lifecycle-rank ``Case`` rather than the raw stored
    string; that annotation is only added on the state sort.
    """
    field = cast(str, _SORT_COLUMNS[key]["order"])
    annotations: dict = {}
    if field == "__state_rank__":
        annotations["state_rank"] = Case(
            *[When(state=value, then=Value(rank)) for value, rank in _STATE_RANK.items()],
            default=Value(len(_STATE_RANK)),
            output_field=IntegerField(),
        )
        field = "state_rank"
    primary = f"-{field}" if desc else field
    terms = [primary] if field == "pk" else [primary, "pk"]
    return terms, annotations


@login_required
def advisory_list(request):
    """List advisories the current user can see.

    Supported query params (all optional):
      ``q``                full-text on summary/details/advisory_id/aliases
      ``project``          project UUID
      ``state``            single value; one of triage|draft|published|dismissed.
                           Surfaced as the state tab strip — absent/invalid means
                           the "All" tab (no state filter).
    """
    user = request.user
    qs = perms.visible_advisories(user)

    # q/project/republish are applied here; ``state`` is applied below so the
    # per-tab counts can be taken on the pre-state queryset.
    qs, applied = _apply_advisory_filters(qs, request)

    # Per-state counts for the tab strip — one GROUP BY over the queryset as
    # narrowed by the *other* filters, so each tab shows how many rows it'd yield
    # (and the counts move with the search box). ``state_total`` backs the "All" tab.
    # ``.order_by()`` is load-bearing: Advisory's default ``-created_at`` ordering
    # would otherwise be folded into this GROUP BY (Django appends ordering columns
    # to the grouping), splitting each state into one row per distinct created_at.
    # The dict comprehension would then keep only the last such row per state and
    # silently undercount. Clearing the ordering keeps it GROUP BY state alone.
    state_counts = {
        row["state"]: row["n"] for row in qs.order_by().values("state").annotate(n=Count("pk"))
    }
    state_total = sum(state_counts.values())

    # The active tab. An absent or unknown state is the "All" tab (no filter).
    # State is deliberately kept out of ``applied`` — the tab strip (its "All"
    # tab) is the clear-state affordance, so it must not drive the form's Clear
    # link, which is only for the search/project/republish filters.
    current_state = request.GET.get("state", "")
    if current_state in dict(State.choices):
        qs = qs.filter(state=current_state)
    else:
        current_state = ""

    sort_key, sort_desc = _parse_sort(request.GET.get("sort", ""))
    order_terms, sort_annotations = _sort_order_by(sort_key, sort_desc)
    qs = qs.select_related("project")
    if sort_annotations:
        qs = qs.annotate(**sort_annotations)  # only paid for on the state sort
    qs = qs.order_by(*order_terms)

    # Hrefs for each tab: the current query string minus ``page`` and ``state``,
    # with the tab's own state re-appended. Building them here keeps query-string
    # assembly out of the template. urlencode escapes values throughout.
    tab_params = request.GET.copy()
    tab_params.pop("page", None)
    tab_params.pop("state", None)

    def _state_href(value: str) -> str:
        params = tab_params.copy()
        if value:
            params["state"] = value
        encoded = params.urlencode()
        return f"?{encoded}" if encoded else request.path

    # Keyed by state value, plus "all" for the no-filter tab ("" is not a usable
    # Django-template dict key).
    state_hrefs = {"all": _state_href("")}
    state_hrefs.update({value: _state_href(value) for value in dict(State.choices)})

    # Sort links for each sortable header. The active column's link points to the
    # flipped direction (so a click toggles it); every other column points to its
    # natural default. ``sort`` is not stripped from tab_params/pager_params, so it
    # rides along across state-tab switches and pagination; here we drop ``page`` so
    # changing the sort returns to page 1.
    sort_base = request.GET.copy()
    sort_base.pop("page", None)

    def _sort_href(key: str) -> str:
        if key == sort_key:
            target = key if sort_desc else f"-{key}"
        else:
            target = f"-{key}" if _SORT_COLUMNS[key]["default_desc"] else key
        params = sort_base.copy()
        params["sort"] = target
        return f"?{params.urlencode()}"

    sort_hrefs = {key: _sort_href(key) for key in _SORT_COLUMNS}
    sort_state = {
        key: {
            "active": key == sort_key,
            "aria": ("descending" if sort_desc else "ascending") if key == sort_key else "none",
            "desc": key == sort_key and sort_desc,
        }
        for key in _SORT_COLUMNS
    }

    # Query string carried into the pager links, sans ``page`` so it can be
    # re-appended. ``urlencode`` escapes values (the old manual loop did neither).
    pager_params = request.GET.copy()
    pager_params.pop("page", None)
    querystring = pager_params.urlencode()

    # Clear target: drop the search/project filters and reset paging, but keep
    # the current state tab + sort. Clearing a filter must not bounce the user
    # back to the All tab (state) or reorder the list (sort) — those are separate
    # axes from the search/project filter the Clear link belongs to.
    clear_params = request.GET.copy()
    for key in ("q", "project", "page"):
        clear_params.pop(key, None)
    clear_encoded = clear_params.urlencode()
    clear_href = f"?{clear_encoded}" if clear_encoded else request.path

    # Cap the page at a reasonable size so a careless filter doesn't
    # render a million rows. Use the same param name as the API.
    try:
        page_size = min(200, max(1, int(request.GET.get("page_size", "50"))))
        page = max(1, int(request.GET.get("page", "1")))
    except (TypeError, ValueError):
        page, page_size = 1, 50
    total = qs.count()
    offset = (page - 1) * page_size
    # Annotate the page slice only (count() above runs on the un-annotated qs):
    # the "Changed since last visit" / "New" subqueries evaluate per fetched row.
    advisories = list(annotate_visit_markers(qs, user)[offset : offset + page_size])
    set_visit_markers(advisories)

    context = {
        "advisories": advisories,
        "filters": applied,
        "current_state": current_state,
        # The active sort, echoed into a hidden form field so the active-search
        # GET preserves it (and the pushed URL stays canonical). Raw is fine: the
        # view re-validates ?sort via _parse_sort on every read.
        "current_sort": request.GET.get("sort", "").strip(),
        "state_counts": state_counts,
        "state_total": state_total,
        "state_hrefs": state_hrefs,
        "sort_hrefs": sort_hrefs,
        "sort_state": sort_state,
        "querystring": querystring,
        "clear_href": clear_href,
        "projects_for_filter": _projects_for_filter(user),
        "total": total,
        "page": page,
        "page_size": page_size,
        "num_pages": max(1, (total + page_size - 1) // page_size),
        "has_next": offset + page_size < total,
        "has_prev": page > 1,
    }
    # Active search: an HTMX GET (from the filter form) gets just the results
    # table, with the tab strip + result count refreshed out-of-band. A normal
    # navigation (or JS/HTMX off) renders the full page.
    template = (
        "advisories/_list_fragment.html"
        if getattr(request, "htmx", False)
        else "advisories/list.html"
    )
    return render(request, template, context)


def _apply_advisory_filters(qs, request):
    """Translate ?q/?project into a queryset.

    ``state`` is intentionally *not* handled here — ``advisory_list`` applies it
    after taking the per-tab counts, and deliberately keeps it out of the returned
    dict so the active tab doesn't trigger the form's Clear link. Returns
    (filtered_qs, applied_filters_dict); the latter is a flat dict the template uses
    to repopulate the search/project form and to show the Clear link.
    """
    applied: dict[str, object] = {}
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

    # Opening the detail page is the canonical "I've seen the current state":
    # clear this advisory's inbox notifications for the viewer, and stamp the
    # visit that drives the "Changed since last visit" / "New" markers. Both
    # run only after the can_view guard above, and are cheap single statements.
    # NOTE: pass an explicit ``last_visited_at`` — with ``auto_now=True`` and an
    # empty ``defaults`` an existing row would not be UPDATEd, so the timestamp
    # would never advance past the first visit.
    from notifications.services import mark_advisory_read

    mark_advisory_read(request.user, advisory)
    AdvisoryVisit.objects.update_or_create(
        user=request.user,
        advisory=advisory,
        defaults={"last_visited_at": timezone.now()},
    )

    last_publication_task = None
    try:
        last_publication_task = advisory.publication_tasks.prefetch_related("artifacts").first()
    except Exception:
        pass

    # A withdrawal is "in progress" while its publication task is queued/running
    # (mirrors publish()'s own in-flight guard, order-independent). When the
    # withdrawal failed instead, the sidebar offers a "Retry withdrawal" action
    # rather than a dead-end "pending" hint (INV-WITHDRAW).
    from publication.models import PublicationTaskStatus

    withdrawal_in_progress = (
        bool(advisory.withdrawn_reason)
        and advisory.publication_tasks.filter(
            status__in=[PublicationTaskStatus.QUEUED, PublicationTaskStatus.RUNNING]
        ).exists()
    )

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
        _mention_candidates(advisory, viewer=request.user)
        if perms.can_comment(request.user, advisory)
        else []
    )

    return render(
        request,
        "advisories/detail.html",
        {
            "advisory": advisory,
            "viewer_can_see_emails": perms.can_see_user_emails(request.user, advisory),
            "mention_candidates": mention_candidates,
            "can_edit": perms.can_edit(request.user, advisory),
            "can_dismiss": perms.can_dismiss(request.user, advisory),
            "can_reopen": perms.can_reopen(request.user, advisory),
            "can_withdraw_published": perms.can_withdraw_published(request.user, advisory),
            "can_request_withdrawal": perms.can_request_withdrawal(request.user, advisory),
            "can_cancel_withdrawal_request": perms.can_cancel_withdrawal_request(
                request.user, advisory
            ),
            "can_approve_withdrawal": perms.can_approve_withdrawal(request.user, advisory),
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
            "withdrawal_in_progress": withdrawal_in_progress,
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
            # Draft admin-reassignment request (INV-AUTH-9). Display-only gates;
            # the views/services re-enforce authorization server-side.
            "can_request_reassignment": perms.can_request_reassignment(request.user, advisory),
            "can_withdraw_reassignment": perms.can_withdraw_reassignment_request(
                request.user, advisory
            ),
            "can_accept_reassignment": perms.can_accept_reassignment_suggestion(
                request.user, advisory
            ),
            "can_pick_reassignment_target": perms.can_pick_reassignment_target(
                request.user, advisory
            ),
            "reassignable_projects": _suggestable_projects(advisory),
            # Display-only gate for the duplicate-check panel loader; the
            # similarity endpoints re-enforce the owner check server-side.
            "similarity_enabled": settings.SIMILARITY_CHECK_ENABLED
            and perms.resolved_permission(request.user, advisory) == "owner",
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
        if advisory.kind == Kind.GHSA_LINKED:
            lifecycle = (
                "Mirrored from GitHub (triage). Advances automatically when the "
                "GHSA is accepted (→ draft) or published — no manual action here."
            )
        else:
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
                # Best-effort duplicate detection (no-op while disabled,
                # never fails creation).
                from similarity.services import request_check_safe

                request_check_safe(advisory, by=user)
                messages.success(request, "Advisory created.")
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
    # GHSA-linked advisories have no AdvisoryHub-editable fields: the OSV
    # content is synced from the upstream GHSA on GitHub, and the project
    # follows the source repository in PMI (re-homed only by
    # ghsa.services.sync_project_repos_from_pmi — never by hand). Refuse here,
    # before the native form path, so a GHSA row can never reach it.
    if advisory.kind == Kind.GHSA_LINKED:
        raise PermissionDenied(
            "GHSA-linked advisories have no editable fields in AdvisoryHub; "
            "content is synced from GitHub and the project follows the source "
            "repository in PMI."
        )

    user = request.user
    # Combine via primary key set instead of `|` because
    # _projects_user_can_create_for returns a `.distinct()` queryset and
    # Django refuses to OR-combine distinct + non-distinct.
    own_pks = list(_projects_user_can_create_for(user).values_list("pk", flat=True))
    creatable_projects = Project.objects.filter(pk__in=set(own_pks + [advisory.project_id]))
    is_triage = advisory.state == State.TRIAGE

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
                # if_changed: a save that alters no payload-visible field must
                # not mint a duplicate version row (INV-VERSION-1).
                new_version = services.record_advisory_version(
                    updated, editor=user, if_changed=True
                )
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
                    # Re-homing the advisory fulfils any pending admin-reassignment
                    # request (INV-AUTH-9): clear it, exactly as the reassignment
                    # pane's accept would (cause "accepted"). No-op if none pending.
                    services.clear_reassignment_request_if_pending(
                        updated, by=user, cause="accepted"
                    )
                    transaction.on_commit(partial(_queue_advisory_created, updated.pk))
                messages.success(request, "Advisory saved.")
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
                messages.success(request, "Advisory dismissed.")
                return redirect("advisories:detail", advisory_id=advisory.advisory_id)

            # The reusable dismissal core (also used by the GHSA auto-dismiss
            # path). can_dismiss was already checked above; for a CVE-bearing
            # advisory it guarantees an admin actor, so the cascade's admin-gated
            # unassign_cve won't raise here.
            services.dismiss_advisory(advisory, by=request.user, reason=reason)
            messages.success(request, "Advisory dismissed.")
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
    messages.success(request, "Advisory reopened.")
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
def advisory_withdraw(request, advisory_id: str):
    """Withdraw a published advisory (admin / mature-publisher owner).

    Marks the advisory withdrawn in OSV/CSAF (the documents stay in the feed)
    and moves it to dismissed once the re-export pushes (INV-LIFECYCLE-4).
    """
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_withdraw_published(request.user, advisory):
        raise PermissionDenied("You cannot withdraw this advisory.")
    reason = (request.POST.get("reason") or "").strip()
    if not reason:
        return _detail_with_error(request, advisory, "A withdrawal reason is required.")
    from publication.services import PublicationInProgress

    try:
        services.withdraw_advisory(advisory, by=request.user, reason=reason)
    except (ValueError, PublicationInProgress) as exc:
        return _detail_with_error(request, advisory, str(exc))
    messages.success(
        request,
        "Withdrawal started — the advisory will be marked withdrawn once the export pushes.",
    )
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="20/h")
def advisory_request_withdrawal(request, advisory_id: str):
    """A non-mature owner requests withdrawal of a published advisory."""
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_request_withdrawal(request.user, advisory):
        raise PermissionDenied("You cannot request withdrawal of this advisory.")
    note = (request.POST.get("note") or "").strip()
    if not note:
        return _detail_with_error(request, advisory, "A withdrawal note is required.")
    try:
        services.request_withdrawal(advisory, by=request.user, note=note)
    except (ValueError, PermissionDenied) as exc:
        return _detail_with_error(request, advisory, str(exc))
    messages.success(request, "Withdrawal requested — an admin will review it.")
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
def advisory_cancel_withdrawal_request(request, advisory_id: str):
    """Cancel a pending withdrawal request (requesting team or admin)."""
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_cancel_withdrawal_request(request.user, advisory):
        raise PermissionDenied("You cannot cancel this withdrawal request.")
    note = (request.POST.get("note") or "").strip()
    services.cancel_withdrawal_request(advisory, by=request.user, note=note)
    messages.success(request, "Withdrawal request cancelled.")
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
def advisory_approve_withdrawal(request, advisory_id: str):
    """An admin approves a pending withdrawal request — withdraws using its note."""
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_approve_withdrawal(request.user, advisory):
        raise PermissionDenied("You cannot approve this withdrawal request.")
    from publication.services import PublicationInProgress

    reason = (advisory.withdrawal_request_note or "").strip() or "Withdrawal requested by the team."
    try:
        services.withdraw_advisory(advisory, by=request.user, reason=reason)
    except (ValueError, PublicationInProgress) as exc:
        return _detail_with_error(request, advisory, str(exc))
    messages.success(
        request,
        "Withdrawal approved — the advisory will be marked withdrawn once the export pushes.",
    )
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
    """Enqueue the ``advisory_created`` notification (thin view-side alias).

    Delegates to :func:`advisories.services.queue_advisory_created_notification`
    so the same enqueue is reachable from non-view callers (e.g. the
    PMI-driven re-home in ``ghsa.services``).
    """
    services.queue_advisory_created_notification(advisory_pk)


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
    messages.success(request, "Advisory promoted to draft.")
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
    messages.success(request, "Flagged for admin routing.")
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
    messages.success(request, "Routing flag cleared.")
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
            "viewer_can_see_emails": perms.can_see_user_emails(request.user, advisory),
            "can_edit": perms.can_edit(request.user, advisory),
            "can_dismiss": perms.can_dismiss(request.user, advisory),
            "can_reopen": perms.can_reopen(request.user, advisory),
            "can_withdraw_published": perms.can_withdraw_published(request.user, advisory),
            "can_request_withdrawal": perms.can_request_withdrawal(request.user, advisory),
            "can_cancel_withdrawal_request": perms.can_cancel_withdrawal_request(
                request.user, advisory
            ),
            "can_approve_withdrawal": perms.can_approve_withdrawal(request.user, advisory),
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
            # Reassignment-request banner (INV-AUTH-9) — so an inline-error
            # re-render still shows the request banner and its actions.
            "can_request_reassignment": perms.can_request_reassignment(request.user, advisory),
            "can_withdraw_reassignment": perms.can_withdraw_reassignment_request(
                request.user, advisory
            ),
            "can_accept_reassignment": perms.can_accept_reassignment_suggestion(
                request.user, advisory
            ),
            "can_pick_reassignment_target": perms.can_pick_reassignment_target(
                request.user, advisory
            ),
            "reassignable_projects": _suggestable_projects(advisory),
            "error": message,
        },
        status=400,
    )


# ---------------------------------------------------------------------------
# Draft admin-reassignment request (INV-AUTH-9)
# ---------------------------------------------------------------------------


def _suggestable_projects(advisory: Advisory):
    """Projects an admin could re-home this draft to: every project except the
    advisory's current one and the ``unsorted`` sentinel. The suggestion is a
    hint only (it grants no access), so the full roster is offered."""
    return (
        Project.objects.exclude(pk=advisory.project_id)
        .exclude(slug=UNSORTED_PROJECT_SLUG)
        .order_by("name")
    )


@login_required
@require_http_methods(["GET"])
def advisory_request_reassignment_modal(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_request_reassignment(request.user, advisory):
        raise PermissionDenied("Reassignment request is not available for this user/advisory.")
    return render(
        request,
        "advisories/_reassign_request_modal.html",
        {"advisory": advisory, "projects": _suggestable_projects(advisory)},
    )


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="20/h")
def advisory_request_reassignment(request, advisory_id: str):
    """Request reassignment of a draft advisory (rendered in an HTMX modal)."""
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    note = (request.POST.get("note") or "").strip()
    raw_slug = (request.POST.get("suggested_project_slug") or "").strip()
    is_htmx = bool(getattr(request, "htmx", False))

    suggested_project = None
    if raw_slug:
        # Unknown slug → treat as no suggestion (the field is optional and the
        # picker only ever offers real projects); never 500 on a stale value.
        suggested_project = Project.objects.filter(slug=raw_slug).first()

    try:
        services.request_admin_reassignment(
            advisory, by=request.user, note=note, suggested_project=suggested_project
        )
    except ValueError as exc:
        if is_htmx:
            return render(
                request,
                "advisories/_reassign_request_modal.html",
                {
                    "advisory": advisory,
                    "projects": _suggestable_projects(advisory),
                    "error": str(exc),
                },
                status=400,
            )
        return _detail_with_error(request, advisory, str(exc))
    messages.success(request, "Reassignment requested — an admin will re-home this advisory.")
    if is_htmx:
        from django.http import HttpResponse

        resp = HttpResponse(status=204)
        resp["HX-Refresh"] = "true"
        return resp
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["GET"])
def advisory_withdraw_reassignment_modal(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_withdraw_reassignment_request(request.user, advisory):
        raise PermissionDenied("Withdraw is not available for this user/advisory.")
    return render(request, "advisories/_withdraw_request_modal.html", {"advisory": advisory})


@login_required
@require_http_methods(["POST"])
def advisory_withdraw_reassignment(request, advisory_id: str):
    """Withdraw a pending reassignment request (requesting team or admin)."""
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    note = (request.POST.get("note") or "").strip()
    services.withdraw_admin_reassignment(advisory, by=request.user, note=note)
    messages.success(request, "Reassignment request withdrawn.")
    if getattr(request, "htmx", False):
        from django.http import HttpResponse

        resp = HttpResponse(status=204)
        resp["HX-Refresh"] = "true"
        return resp
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
def advisory_accept_reassignment(request, advisory_id: str):
    """Resolve a reassignment request by moving the advisory to a project.

    No ``project_slug`` → one-click accept of the suggested project (non-admin
    target-team members and admins). A ``project_slug`` → the admin's in-banner
    picker chose that project. Authorization is re-checked in the service.
    """
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    raw_slug = (request.POST.get("project_slug") or "").strip()
    new_project = None
    if raw_slug:
        new_project = Project.objects.filter(slug=raw_slug).first()
        if new_project is None:
            return _detail_with_error(request, advisory, f"Unknown project {raw_slug!r}.")
        if new_project.pk == advisory.project_id:
            return _detail_with_error(
                request, advisory, "This advisory is already on that project."
            )
    services.accept_reassignment_suggestion(advisory, by=request.user, new_project=new_project)
    messages.success(request, "Advisory reassigned.")
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


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
            "viewer_can_see_emails": perms.can_see_user_emails(request.user, advisory),
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
