"""Access grant + invitation JSON endpoints."""

from __future__ import annotations

from django.contrib.auth.models import Group
from django.db import transaction
from django.shortcuts import get_object_or_404

from access import services as access_services
from access.models import AdvisoryAccessGrant, Permission
from accounts.models import User
from advisories import permissions as perms
from advisories.models import Advisory
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
from .serializers import grant_to_dict, invitation_to_dict


@require_methods_json(["GET", "POST"])
@login_required_json
@map_permission_denied
@json_ratelimit(rate="20/h")
def grants_collection(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_grant_access(request.user, advisory):
        return error("forbidden", "You cannot manage access on this advisory.", status=403)

    if request.method == "GET":
        return json_response(
            {
                "grants": [grant_to_dict(g) for g in access_services.list_active_grants(advisory)],
                "pending": [
                    invitation_to_dict(i)
                    for i in access_services.list_pending_invitations(advisory)
                ],
            }
        )

    # POST: grant or invite. Body: {principal: "user"|"group"|"email", ...}
    try:
        data = parse_json(request)
    except ValueError as exc:
        return error("invalid_body", str(exc), status=400)

    permission = data.get("permission")
    if permission == "owner":
        return error(
            "invalid_permission",
            "owner is not grantable: it derives from project security team membership.",
            status=400,
        )
    if permission not in dict(Permission.choices):
        return error(
            "invalid_permission", "permission must be one of viewer|collaborator.", status=400
        )

    principal = data.get("principal")
    if principal == "user":
        email = (data.get("email") or "").strip()
        if not email:
            return error("invalid_body", "email is required when principal=user.", status=400)
        with transaction.atomic():
            user = User.objects.filter(email__iexact=email).first()
            if user is None:
                invitation = access_services.invite_email(
                    advisory, email, permission, by=request.user
                )
                _enqueue_invite_email(invitation)
                return json_response(
                    {"created": "invitation", "invitation": invitation_to_dict(invitation)},
                    status=201,
                )
            grant = access_services.grant_to_user(advisory, user, permission, by=request.user)
            return json_response({"created": "grant", "grant": grant_to_dict(grant)}, status=201)

    if principal == "group":
        group_name = (data.get("group") or "").strip()
        if not group_name:
            return error("invalid_body", "group is required when principal=group.", status=400)
        try:
            group = Group.objects.get(name=group_name)
        except Group.DoesNotExist:
            return error("unknown_group", f"Group {group_name!r} does not exist.", status=404)
        grant = access_services.grant_to_group(advisory, group, permission, by=request.user)
        return json_response({"created": "grant", "grant": grant_to_dict(grant)}, status=201)

    return error("invalid_principal", "principal must be 'user' or 'group'.", status=400)


@require_methods_json(["DELETE"])
@login_required_json
@map_permission_denied
def grant_detail(request, advisory_id: str, grant_id: int):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_grant_access(request.user, advisory):
        return error("forbidden", "You cannot manage access on this advisory.", status=403)
    grant = get_object_or_404(AdvisoryAccessGrant, pk=grant_id, advisory=advisory)
    access_services.revoke(grant, by=request.user)
    return json_response({"revoked": grant_id})


def _enqueue_invite_email(invitation):
    if invitation.pk is None:  # transient (existing-user) invitation
        return
    from notifications.tasks import send_invitation_email

    transaction.on_commit(lambda: safe_enqueue(send_invitation_email, invitation.pk))
