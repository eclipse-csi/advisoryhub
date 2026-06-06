"""HTMX endpoints for managing per-advisory access grants and invitations."""

from __future__ import annotations

import json
from typing import Any

from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_http_methods

from accounts.models import User
from advisories import permissions as perms
from advisories.models import Advisory
from common.enqueue import safe_enqueue
from common.ratelimit import html_ratelimit

from . import services
from .models import AdvisoryAccessGrant, PendingInvitation, Permission, PrincipalType


@login_required
@require_http_methods(["GET"])
def access_panel(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_grant_access(request.user, advisory):
        raise PermissionDenied("You cannot manage access on this advisory.")
    return render(
        request,
        "access/_panel.html",
        _panel_context(advisory, request.user),
    )


OWNER_SECTION_KEY = "owner"


def _panel_context(advisory: Advisory, user: User) -> dict:
    # Sections: grantable buckets keyed by Permission, plus a derived "owner"
    # bucket for the project security team. Owner is not a grant value, so it
    # doesn't appear in `Permission.values`.
    sections: dict[str, list[dict]] = {OWNER_SECTION_KEY: []}
    for value in Permission.values:
        sections[value] = []

    # Pinned row: the project's security team is always an owner via the
    # permission resolver, so surface it as a locked entry rather than leaving
    # it implicit.
    security_team = advisory.project.security_team
    security_team_id = advisory.project.security_team_id
    sections[OWNER_SECTION_KEY].append(
        {
            "type": "system",
            "id": None,
            "label": f"@{security_team.name}",
            "kind": "group",
            "permission": OWNER_SECTION_KEY,
            "pending": False,
            "locked": True,
        }
    )

    for g in services.list_active_grants(advisory):
        # Hide explicit grants that duplicate the pinned security-team row —
        # they have no effect on the resolved permission, so showing them
        # would be misleading.
        if g.principal_type == PrincipalType.GROUP and g.principal_id == security_team_id:
            continue
        principal = g.principal()
        user_obj = None
        if isinstance(principal, User):
            label = principal.display_label(fallback=principal.email or "")
            kind = "user"
            user_obj = principal
        elif isinstance(principal, Group):
            label = f"@{principal.name}"
            kind = "group"
        else:
            label = f"#{g.principal_id}"
            kind = g.principal_type
        if g.permission not in sections:
            # Should not happen post-migration, but skip rather than crash if
            # a stale value lingers.
            continue
        sections[g.permission].append(
            {
                "type": "grant",
                "id": g.pk,
                "label": label,
                "kind": kind,
                "user": user_obj,
                "permission": g.permission,
                "pending": False,
            }
        )

    for inv in services.list_pending_invitations(advisory):
        if inv.permission not in sections:
            continue
        sections[inv.permission].append(
            {
                "type": "invitation",
                "id": inv.pk,
                "label": inv.email,
                "kind": "invitation",
                "permission": inv.permission,
                "pending": True,
                "expires_at": inv.expires_at,
            }
        )

    for rows in sections.values():
        rows.sort(
            key=lambda r: (
                0 if r.get("locked") else 1,
                0 if r["kind"] != "group" else 1,
                r["label"].lower(),
            )
        )

    # Order sections by privilege, highest first.
    permission_order = [
        (OWNER_SECTION_KEY, "Owners"),
        (Permission.COLLABORATOR, "Collaborators"),
        (Permission.VIEWER, "Viewers"),
    ]
    ordered_sections = [
        {"permission": value, "label": label, "rows": sections.get(value, [])}
        for value, label in permission_order
    ]

    return {
        "advisory": advisory,
        "viewer_can_see_emails": perms.can_see_user_emails(user, advisory),
        "sections": ordered_sections,
        "permission_choices": Permission.choices,
        "groups_available": [g.name for g in services.groups_grantable_by(user)],
    }


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="20/h")
def batch_save(request, advisory_id: str):
    """Apply a batched set of access-panel edits atomically.

    Body JSON:
    {
      "grants_add": [{"principal": "alice@example.org" | "@group-name",
                       "permission": "viewer|collaborator"}, ...],
      "grants_update": [{"id": <grant_pk>, "permission": "..."}, ...],
      "grants_revoke": [<grant_pk>, ...],
      "invitations_revoke": [<invitation_pk>, ...]
    }
    """
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_grant_access(request.user, advisory):
        raise PermissionDenied()

    try:
        payload = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return HttpResponseBadRequest("invalid JSON")
    if not isinstance(payload, dict):
        return HttpResponseBadRequest("payload must be an object")

    adds = payload.get("grants_add") or []
    updates = payload.get("grants_update") or []
    revokes = payload.get("grants_revoke") or []
    inv_updates = payload.get("invitations_update") or []
    inv_revokes = payload.get("invitations_revoke") or []

    # ---- validate everything before touching the DB -----------------------
    parsed_adds: list[dict] = []
    errors: list[str] = []

    for item in adds:
        if not isinstance(item, dict):
            errors.append("grants_add entries must be objects")
            continue
        principal_raw = (item.get("principal") or "").strip()
        permission = item.get("permission")
        if not principal_raw:
            errors.append("missing principal")
            continue
        if permission == "owner":
            errors.append(
                "owner is not grantable: it derives from project security team membership."
            )
            continue
        if permission not in Permission.values:
            errors.append(f"unknown permission {permission!r}")
            continue
        if principal_raw.startswith("@"):
            group_name = principal_raw[1:].strip()
            if not group_name:
                errors.append("group name is empty")
                continue
            grantable = {g.name for g in services.groups_grantable_by(request.user)}
            if group_name not in grantable:
                errors.append(f"group @{group_name} is not available for granting")
                continue
            try:
                group = Group.objects.get(name=group_name)
            except Group.DoesNotExist:
                errors.append(f"unknown group @{group_name}")
                continue
            if group.pk == advisory.project.security_team_id:
                errors.append(
                    f"@{group_name} is the project security team — it already has owner access."
                )
                continue
            parsed_adds.append({"kind": "group", "group": group, "permission": permission})
        else:
            email = principal_raw
            user = User.objects.filter(email__iexact=email).first()
            parsed_adds.append(
                {"kind": "user", "email": email, "user": user, "permission": permission}
            )

    parsed_updates: list[tuple[AdvisoryAccessGrant, str]] = []
    for item in updates:
        if not isinstance(item, dict):
            errors.append("grants_update entries must be objects")
            continue
        permission = item.get("permission")
        grant_id: Any = item.get("id")  # untrusted JSON pk; validated by the filter below
        if permission == "owner":
            errors.append(
                "owner is not grantable: it derives from project security team membership."
            )
            continue
        if permission not in Permission.values:
            errors.append(f"unknown permission {permission!r}")
            continue
        grant = AdvisoryAccessGrant.objects.filter(pk=grant_id, advisory=advisory).first()
        if grant is None:
            errors.append(f"unknown grant {grant_id}")
            continue
        parsed_updates.append((grant, permission))

    parsed_revokes: list[AdvisoryAccessGrant] = []
    for grant_id in revokes:
        grant = AdvisoryAccessGrant.objects.filter(pk=grant_id, advisory=advisory).first()
        if grant is None:
            errors.append(f"unknown grant {grant_id}")
            continue
        parsed_revokes.append(grant)

    parsed_inv_updates: list[tuple[PendingInvitation, str]] = []
    for item in inv_updates:
        if not isinstance(item, dict):
            errors.append("invitations_update entries must be objects")
            continue
        permission = item.get("permission")
        inv_id: Any = item.get("id")  # untrusted JSON pk; validated by the filter below
        if permission == "owner":
            errors.append(
                "owner is not grantable: it derives from project security team membership."
            )
            continue
        if permission not in Permission.values:
            errors.append(f"unknown permission {permission!r}")
            continue
        inv = PendingInvitation.objects.filter(
            pk=inv_id, advisory=advisory, redeemed_at__isnull=True
        ).first()
        if inv is None:
            errors.append(f"unknown invitation {inv_id}")
            continue
        parsed_inv_updates.append((inv, permission))

    parsed_inv_revokes: list[PendingInvitation] = []
    for inv_id in inv_revokes:
        inv = PendingInvitation.objects.filter(
            pk=inv_id, advisory=advisory, redeemed_at__isnull=True
        ).first()
        if inv is None:
            errors.append(f"unknown invitation {inv_id}")
            continue
        parsed_inv_revokes.append(inv)

    if errors:
        return JsonResponse({"ok": False, "errors": errors}, status=400)

    # ---- apply -----------------------------------------------------------
    with transaction.atomic():
        for entry in parsed_adds:
            if entry["kind"] == "group":
                services.grant_to_group(
                    advisory, entry["group"], entry["permission"], by=request.user
                )
            elif entry["user"] is not None:
                services.grant_to_user(
                    advisory, entry["user"], entry["permission"], by=request.user
                )
            else:
                services.invite_email(
                    advisory, entry["email"], entry["permission"], by=request.user
                )
                _queue_invite_email_for_latest(advisory, entry["email"])

        for grant, permission in parsed_updates:
            principal = grant.principal()
            if isinstance(principal, User):
                services.grant_to_user(advisory, principal, permission, by=request.user)
            elif isinstance(principal, Group):
                services.grant_to_group(advisory, principal, permission, by=request.user)

        for grant in parsed_revokes:
            services.revoke(grant, by=request.user)

        for inv, permission in parsed_inv_updates:
            services.update_invitation_permission(inv, permission, by=request.user)

        for inv in parsed_inv_revokes:
            services.revoke_invitation(inv, by=request.user)

    return render(request, "access/_panel.html", _panel_context(advisory, request.user))


def _queue_invite_email_for_latest(advisory, email):
    invite = (
        advisory.pending_invitations.filter(email__iexact=email).order_by("-created_at").first()
    )
    if invite is None:
        return
    from notifications.tasks import send_invitation_email

    transaction.on_commit(lambda: safe_enqueue(send_invitation_email, invite.pk))
