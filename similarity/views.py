"""Owner-only HTMX endpoints for the duplicate-check sidebar panel.

Both endpoints enforce the owner gate server-side (INV-SIM-1) — the
``similarity_enabled`` flag the detail template uses is display-only — and
404 while the feature is disabled, so the surface doesn't exist at all when
no LLM provider is configured (INV-SIM-2).
"""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_http_methods

from advisories import permissions as perms
from advisories.models import Advisory
from common.ratelimit import html_ratelimit

from . import services
from .models import SimilarityCheckStatus


def _gated_advisory(request, advisory_id: str) -> Advisory:
    if not settings.SIMILARITY_CHECK_ENABLED:
        raise Http404
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if perms.resolved_permission(request.user, advisory) != "owner":
        raise PermissionDenied("You cannot view duplicate-check results for this advisory.")
    return advisory


@login_required
@require_http_methods(["GET"])
def similarity_panel(request, advisory_id: str):
    """HTMX fragment: the latest check's state and its matches."""
    advisory = _gated_advisory(request, advisory_id)
    return render(request, "similarity/_panel.html", _panel_context(advisory))


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="10/h")
def similarity_run(request, advisory_id: str):
    """Queue a (re-)check and re-render the panel."""
    advisory = _gated_advisory(request, advisory_id)
    try:
        services.request_check(advisory, by=request.user)
    except services.SimilarityCheckInProgress:
        pass  # the re-rendered panel shows the pending state
    return render(request, "similarity/_panel.html", _panel_context(advisory))


def _panel_context(advisory: Advisory) -> dict:
    check = advisory.similarity_checks.first()  # Meta.ordering → latest
    candidates = (
        list(check.candidates.select_related("matched_advisory").order_by("rank"))
        if check is not None and check.status == SimilarityCheckStatus.SUCCEEDED
        else []
    )
    is_pending = check is not None and check.status in (
        SimilarityCheckStatus.QUEUED,
        SimilarityCheckStatus.RUNNING,
    )
    return {
        "advisory": advisory,
        "check": check,
        "candidates": candidates,
        "is_pending": is_pending,
    }
