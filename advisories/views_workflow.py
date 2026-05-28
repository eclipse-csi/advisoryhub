"""Advisory workflow action endpoints (Phase C).

These live in their own module so the main ``views.py`` stays focused on
CRUD. All entry points enforce authorization through the permissions
service before delegating to ``workflows.services``.
"""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_http_methods

from advisories import permissions as perms
from advisories.models import Advisory
from workflows import services as wf
from workflows.models import ReviewTask, ReviewTaskStatus


@login_required
@require_http_methods(["POST"])
def request_cve(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    wf.request_cve(advisory, by=request.user)  # raises PermissionDenied on its own
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
def unassign_cve(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    reason = request.POST.get("reason", "")
    wf.unassign_cve(advisory, by=request.user, reason=reason)
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
def submit_for_review(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    wf.submit_for_review(advisory, by=request.user)
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
def reopen_review(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    wf.reopen_review(advisory, by=request.user)
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
def withdraw_review(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    wf.withdraw_review(advisory, by=request.user)
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
def revoke_approval(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    reason = request.POST.get("reason", "")
    wf.revoke_approval(advisory, by=request.user, reason=reason)
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


_REVIEW_DECISIONS = {
    ReviewTaskStatus.APPROVED: wf.approve_review,
    ReviewTaskStatus.CHANGES_REQUESTED: wf.request_changes,
}


@login_required
@require_http_methods(["POST"])
def review_decide(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_review(request.user):
        raise PermissionDenied("You cannot decide reviews.")
    task = get_object_or_404(ReviewTask, advisory=advisory, status=ReviewTaskStatus.OPEN)
    decision = request.POST.get("decision", "")
    action = _REVIEW_DECISIONS.get(decision)
    if action is None:
        return HttpResponseBadRequest(f"Unknown decision {decision!r}")
    notes = request.POST.get("notes", "")
    action(task, by=request.user, notes=notes)
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)
