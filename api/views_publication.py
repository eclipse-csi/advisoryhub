"""Publication status / retry / artifact JSON endpoints."""

from __future__ import annotations

from django.shortcuts import get_object_or_404
from django.urls import reverse

from accounts.step_up import is_step_up_fresh, step_up_required
from advisories import permissions as perms
from advisories.models import Advisory
from common.ratelimit import json_ratelimit
from publication import services as pub_services
from publication.models import PublicationArtifact, PublicationTask, PublicationTaskStatus

from .responses import (
    error,
    json_response,
    login_required_json,
    map_permission_denied,
    require_methods_json,
)
from .serializers import publication_task_to_dict


@require_methods_json(["GET"])
@login_required_json
@map_permission_denied
def publication_status(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_view(request.user, advisory):
        return error("forbidden", "You do not have access to this advisory.", status=403)
    tasks = list(advisory.publication_tasks.prefetch_related("artifacts").order_by("-created_at"))
    return json_response({"tasks": [publication_task_to_dict(t) for t in tasks]})


def _step_up_response_or_none(request):
    """Return a 401 step_up_required response if step-up isn't fresh."""
    if not step_up_required():
        return None
    if is_step_up_fresh(request):
        return None
    return error(
        "step_up_required",
        "Re-authenticate before publishing.",
        status=401,
        step_up_url=reverse("step_up_initiate"),
    )


@require_methods_json(["POST"])
@login_required_json
@map_permission_denied
@json_ratelimit(rate="10/h")
def publish(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    step_up = _step_up_response_or_none(request)
    if step_up is not None:
        return step_up
    try:
        task = pub_services.publish(advisory, by=request.user)
    except pub_services.PublicationInProgress as exc:
        return error("in_progress", str(exc), status=409)
    return json_response(publication_task_to_dict(task), status=202)


@require_methods_json(["POST"])
@login_required_json
@map_permission_denied
@json_ratelimit(rate="10/h")
def retry_task(request, task_id: int):
    task = get_object_or_404(PublicationTask, pk=task_id)
    if not perms.can_publish(request.user, task.advisory):
        return error("forbidden", "You cannot retry this publication.", status=403)
    if task.status != PublicationTaskStatus.FAILED:
        return error(
            "not_failed",
            "Only failed publication tasks can be retried.",
            status=400,
        )
    step_up = _step_up_response_or_none(request)
    if step_up is not None:
        return step_up
    new_task = pub_services.retry(task, by=request.user)
    return json_response(publication_task_to_dict(new_task), status=202)


@require_methods_json(["GET"])
@login_required_json
@map_permission_denied
def artifact_preview(request, task_id: int, kind: str):
    task = get_object_or_404(PublicationTask, pk=task_id)
    if not perms.can_view(request.user, task.advisory):
        return error("forbidden", "You do not have access to this advisory.", status=403)
    if kind not in (PublicationArtifact.Kind.OSV, PublicationArtifact.Kind.CSAF):
        return error("invalid_kind", f"Unknown artifact kind {kind!r}.", status=400)
    artifact = get_object_or_404(PublicationArtifact, task=task, kind=kind)
    return json_response(
        {
            "kind": artifact.kind,
            "path": artifact.path,
            "content": artifact.content,
        }
    )
