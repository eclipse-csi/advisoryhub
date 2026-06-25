"""CVE Assignment queue + HTMX action endpoints."""

from __future__ import annotations

from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_http_methods

from advisories.models import Advisory
from workflows import services as wf
from workflows.models import (
    CveRequestStatus,
    CveRequestTask,
    OrphanCve,
    OrphanCveReassignmentStatus,
    OrphanCveReassignmentTask,
    OrphanCveStatus,
)

from .base import admin_required


@admin_required
def cves(request):
    cve_open = list(
        CveRequestTask.objects.filter(status=CveRequestStatus.QUEUED)
        .select_related("advisory", "advisory__project", "requested_by", "assignee")
        .prefetch_related("requested_by__groups", "assignee__groups")
        .order_by("-created_at")
    )
    orphan_open = list(
        OrphanCve.objects.filter(status=OrphanCveStatus.ORPHANED)
        .select_related("previous_advisory", "unassigned_by")
        .prefetch_related("unassigned_by__groups")
        .order_by("-unassigned_at")
    )
    orphan_resolved = list(
        OrphanCve.objects.filter(status=OrphanCveStatus.MARKED_REJECTED)
        .select_related("previous_advisory", "marked_rejected_by")
        .prefetch_related("marked_rejected_by__groups")
        .order_by("-marked_rejected_at")[:25]
    )
    reassignment_open = list(
        OrphanCveReassignmentTask.objects.filter(status=OrphanCveReassignmentStatus.QUEUED)
        .select_related("advisory", "advisory__project", "orphan_cve", "requested_by")
        .prefetch_related("requested_by__groups")
        .order_by("-created_at")
    )
    banned_advisories = list(
        Advisory.objects.filter(cve_requests_banned=True)
        .select_related("project")
        .order_by("advisory_id")
    )
    return render(
        request,
        "admin_console/cves.html",
        {
            "cve_open": cve_open,
            "orphan_open": orphan_open,
            "orphan_resolved": orphan_resolved,
            "reassignment_open": reassignment_open,
            "banned_advisories": banned_advisories,
            "cve_status_choices": CveRequestStatus.choices,
            "admin_section": "cves",
        },
    )


@admin_required
@require_http_methods(["GET"])
def cve_reject_modal(request, task_id: int):
    """Return the HTMX-swappable rejection modal for a queued CVE request."""
    task = get_object_or_404(CveRequestTask, pk=task_id)
    return render(request, "admin_console/_cve_reject_modal.html", {"task": task})


@admin_required
@require_http_methods(["POST"])
def cve_transition(request, task_id: int):
    task = get_object_or_404(CveRequestTask, pk=task_id)
    new_status = request.POST.get("status", "")
    cve_id = request.POST.get("cve_id") or None
    notes = request.POST.get("notes") or None
    ban_future_requests = request.POST.get("ban_future_requests") == "1"
    try:
        wf.transition_cve_request(
            task,
            by=request.user,
            new_status=new_status,
            cve_id=cve_id,
            notes=notes,
            ban_future_requests=ban_future_requests,
        )
    except (ValueError, PermissionDenied) as exc:
        return render(
            request,
            "admin_console/_cve_row.html",
            {"task": task, "error": str(exc)},
            status=400,
        )
    task.refresh_from_db()
    return render(request, "admin_console/_cve_row.html", {"task": task})


@admin_required
@require_http_methods(["POST"])
def cve_allow(request, advisory_id: str):
    """Lift a CVE-request ban so the advisory's owner can request a CVE again."""
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    try:
        wf.unban_cve_requests(advisory, by=request.user)
    except (ValueError, PermissionDenied) as exc:
        return render(
            request,
            "admin_console/_cve_banned_row.html",
            {"advisory": advisory, "error": str(exc)},
            status=400,
        )
    advisory.refresh_from_db()
    return render(request, "admin_console/_cve_banned_row.html", {"advisory": advisory})


@admin_required
@require_http_methods(["POST"])
def orphan_reassignment_resolve(request, task_id: int):
    """Resolve an orphan CVE reassignment task created by the reopen flow."""
    task = get_object_or_404(OrphanCveReassignmentTask, pk=task_id)
    outcome = request.POST.get("outcome", "")
    replacement_cve_id = request.POST.get("replacement_cve_id", "")
    notes = request.POST.get("notes", "")
    try:
        wf.resolve_reassignment_task(
            task,
            by=request.user,
            outcome=outcome,
            replacement_cve_id=replacement_cve_id,
            notes=notes,
        )
    except (ValueError, PermissionDenied) as exc:
        return render(
            request,
            "admin_console/_reassignment_row.html",
            {"task": task, "error": str(exc)},
            status=400,
        )
    task.refresh_from_db()
    return render(request, "admin_console/_reassignment_row.html", {"task": task})


@admin_required
@require_http_methods(["POST"])
def orphan_mark_rejected(request, orphan_id: int):
    orphan = get_object_or_404(OrphanCve, pk=orphan_id)
    notes = request.POST.get("notes", "")
    try:
        wf.mark_orphan_rejected(orphan, by=request.user, notes=notes)
    except (ValueError, PermissionDenied) as exc:
        return render(
            request,
            "admin_console/_orphan_row.html",
            {"orphan": orphan, "error": str(exc)},
            status=400,
        )
    orphan.refresh_from_db()
    return render(request, "admin_console/_orphan_row.html", {"orphan": orphan})
