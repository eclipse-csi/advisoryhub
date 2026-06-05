"""HTTP endpoints for publishing, retrying, and previewing artifacts."""

from __future__ import annotations

import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from accounts.step_up import require_step_up_or_redirect
from advisories import permissions as perms
from advisories.models import Advisory
from common.ratelimit import html_ratelimit

from . import services
from .models import PublicationArtifact, PublicationTask, PublicationTaskStatus


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="10/h")
def publish(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    # Publishing pushes to a public Git repo; require a fresh OIDC
    # re-auth regardless of how long the session has been alive.
    redirect_resp = require_step_up_or_redirect(request, next_url=request.path)
    if redirect_resp is not None:
        return redirect_resp
    try:
        services.publish(advisory, by=request.user)
    except services.PublicationInProgress as exc:
        messages.warning(request, str(exc))
    else:
        messages.success(request, "Publication started.")
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="10/h")
def retry(request, task_id: int):
    task = get_object_or_404(PublicationTask, pk=task_id)
    if not perms.can_publish(request.user, task.advisory):
        raise PermissionDenied("You cannot retry this publication.")
    if task.status != PublicationTaskStatus.FAILED:
        return HttpResponseBadRequest("Task is not in 'failed' state.")
    redirect_resp = require_step_up_or_redirect(request, next_url=request.path)
    if redirect_resp is not None:
        return redirect_resp
    services.retry(task, by=request.user)
    messages.success(request, "Publication retry started.")
    return redirect("admin_console:index")


@login_required
@require_http_methods(["GET"])
def artifact_preview(request, task_id: int, kind: str):
    task = get_object_or_404(PublicationTask, pk=task_id)
    if not perms.can_view(request.user, task.advisory):
        raise PermissionDenied()
    if kind not in (
        PublicationArtifact.Kind.OSV,
        PublicationArtifact.Kind.CSAF,
        PublicationArtifact.Kind.CVE,
    ):
        return HttpResponseBadRequest("Unknown artifact kind.")
    artifact = get_object_or_404(PublicationArtifact, task=task, kind=kind)
    pretty = json.dumps(artifact.content, indent=2, sort_keys=True, ensure_ascii=False)
    return render(
        request,
        "publication/artifact.html",
        {"task": task, "artifact": artifact, "pretty": pretty},
    )


@login_required
@require_http_methods(["GET"])
def artifact_download(request, task_id: int, kind: str):
    task = get_object_or_404(PublicationTask, pk=task_id)
    if not perms.can_view(request.user, task.advisory):
        raise PermissionDenied()
    artifact = get_object_or_404(PublicationArtifact, task=task, kind=kind)
    pretty = json.dumps(artifact.content, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    response = HttpResponse(pretty, content_type="application/json")
    response["Content-Disposition"] = (
        f'attachment; filename="{task.advisory.advisory_id}.{kind}.json"'
    )
    return response
