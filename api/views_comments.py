"""Comment listing + creation JSON endpoints."""

from __future__ import annotations

from django.db import transaction
from django.shortcuts import get_object_or_404

from advisories import permissions as perms
from advisories.models import Advisory
from comments import services as comment_services
from common.enqueue import safe_enqueue
from common.ratelimit import json_ratelimit

from .responses import (
    error,
    json_response,
    login_required_json,
    map_permission_denied,
    parse_json,
    require_methods_json,
)
from .serializers import comment_to_dict


@require_methods_json(["GET", "POST"])
@login_required_json
@map_permission_denied
@json_ratelimit(rate="30/m")
def comments_collection(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_view(request.user, advisory):
        return error("forbidden", "You do not have access to this advisory.", status=403)

    if request.method == "GET":
        qs = advisory.comments.select_related("author").order_by("created_at")
        if not perms.can_see_internal_comment(request.user, advisory):
            qs = qs.exclude(is_internal=True)
        return json_response({"results": [comment_to_dict(c) for c in qs]})

    # POST
    if not perms.can_comment(request.user, advisory):
        return error("forbidden", "You cannot comment on this advisory.", status=403)
    try:
        data = parse_json(request)
    except ValueError as exc:
        return error("invalid_body", str(exc), status=400)
    body = (data.get("body") or "").strip()
    if not body:
        return error("invalid_body", "body is required and non-empty.", status=400)
    internal = bool(data.get("is_internal", False))

    with transaction.atomic():
        comment = comment_services.add_comment(
            advisory, author=request.user, body=body, internal=internal
        )
        from notifications.tasks import send_comment_email

        transaction.on_commit(lambda: safe_enqueue(send_comment_email, advisory.pk, comment.pk))

    return json_response(comment_to_dict(comment), status=201)
