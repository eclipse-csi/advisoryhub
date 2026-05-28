"""Advisory list/detail JSON endpoints."""

from __future__ import annotations

import uuid

from django.db.models import Q
from django.http import Http404
from django.shortcuts import get_object_or_404

from advisories import permissions as perms
from advisories.models import Advisory, State

from .responses import (
    error,
    json_response,
    login_required_json,
    map_permission_denied,
    require_methods_json,
)
from .serializers import advisory_summary_to_dict, advisory_to_dict


@require_methods_json(["GET"])
@login_required_json
def advisory_list(request):
    """List advisories visible to the authenticated user.

    Query params:
      ``q``              full-text on summary/details/aliases (substring)
      ``project``        project UUID filter
      ``state``          one of draft|published|dismissed
      ``review_status``  one of none|submitted|...
      ``page``           1-indexed
      ``page_size``      default 25, max 100
    """
    user = request.user
    qs = _visible_qs(user)

    if project := request.GET.get("project"):
        try:
            project_uuid = uuid.UUID(project)
        except ValueError:
            return error("invalid_project", "project must be a UUID", status=400)
        qs = qs.filter(project_id=project_uuid)
    if state := request.GET.get("state"):
        if state not in dict(State.choices):
            return error("invalid_state", f"Unknown state {state!r}", status=400)
        qs = qs.filter(state=state)
    if review_status := request.GET.get("review_status"):
        qs = qs.filter(review_status=review_status)
    if q := request.GET.get("q"):
        qs = qs.filter(
            Q(summary__icontains=q)
            | Q(details__icontains=q)
            | Q(advisory_id__icontains=q)
            | Q(aliases__icontains=q)
        )

    try:
        page = max(1, int(request.GET.get("page", "1")))
        page_size = min(100, max(1, int(request.GET.get("page_size", "25"))))
    except (TypeError, ValueError):
        return error("invalid_pagination", "page/page_size must be integers", status=400)

    total = qs.count()
    offset = (page - 1) * page_size
    rows = list(qs.select_related("project")[offset : offset + page_size])

    return json_response(
        {
            "results": [advisory_summary_to_dict(a) for a in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }
    )


@require_methods_json(["GET"])
@login_required_json
@map_permission_denied
def advisory_detail(request, advisory_id: str):
    advisory = _get_or_404(advisory_id)
    if not perms.can_view(request.user, advisory):
        return error("forbidden", "You do not have access to this advisory.", status=403)
    return json_response(advisory_to_dict(advisory))


# ---- helpers --------------------------------------------------------------


def _visible_qs(user):
    """Queryset of advisories the user can see (admins see all)."""
    return perms.visible_advisories(user)


def _get_or_404(advisory_id: str) -> Advisory:
    try:
        return get_object_or_404(Advisory, advisory_id=advisory_id)
    except Http404:
        raise
