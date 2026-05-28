"""JSON endpoints for the security-team dashboard tasks (CVE + review)."""

from __future__ import annotations

from typing import Any

from django.shortcuts import get_object_or_404

from advisories import permissions as perms
from workflows import services as wf
from workflows.models import (
    CveRequestStatus,
    CveRequestTask,
    ReviewTask,
    ReviewTaskStatus,
)

from .responses import (
    error,
    json_response,
    login_required_json,
    map_permission_denied,
    parse_json,
    require_methods_json,
)
from .serializers import cve_task_to_dict, review_task_to_dict


@require_methods_json(["POST"])
@login_required_json
@map_permission_denied
def cve_transition(request, task_id: int):
    if not perms.can_review(request.user):
        return error("forbidden", "Admin/security team only.", status=403)
    task = get_object_or_404(CveRequestTask, pk=task_id)
    try:
        data = parse_json(request)
    except ValueError as exc:
        return error("invalid_body", str(exc), status=400)
    new_status = data.get("status")
    if new_status not in dict(CveRequestStatus.choices):
        return error("invalid_status", f"Unknown CVE status {new_status!r}.", status=400)
    try:
        wf.transition_cve_request(
            task,
            by=request.user,
            new_status=new_status,
            cve_id=data.get("cve_id") or None,
            notes=data.get("notes") or None,
        )
    except ValueError as exc:
        return error("invalid_transition", str(exc), status=400)
    except Exception as exc:
        return error("validation_failed", str(exc), status=400)
    task.refresh_from_db()
    return json_response(cve_task_to_dict(task))


@require_methods_json(["POST"])
@login_required_json
@map_permission_denied
def review_decide(request, task_id: int):
    if not perms.can_review(request.user):
        return error("forbidden", "Admin/security team only.", status=403)
    task = get_object_or_404(ReviewTask, pk=task_id)
    try:
        data = parse_json(request)
    except ValueError as exc:
        return error("invalid_body", str(exc), status=400)
    decision: Any = data.get("decision")  # untrusted JSON; matched against the dict below
    notes = (data.get("notes") or "").strip()

    fn = {
        ReviewTaskStatus.APPROVED: wf.approve_review,
        ReviewTaskStatus.CHANGES_REQUESTED: wf.request_changes,
    }.get(decision)
    if fn is None:
        return error("invalid_decision", f"Unknown decision {decision!r}.", status=400)
    try:
        fn(task, by=request.user, notes=notes)
    except Exception as exc:
        return error("review_failed", str(exc), status=400)
    task.refresh_from_db()
    return json_response(review_task_to_dict(task))
