"""Read-only Users directory for the admin console.

Aggregates per-user the information an admin would otherwise have to assemble
from `/django-admin/`, the access panel of each advisory, and the project
pages: group membership, project security-team memberships (which confer
owner per INV-AUTH-3), direct and group-inherited advisory grants, pending
invitations to the user's email, and notification preferences.

No mutations: every view renders only. INV-AUTH-1 is enforced by
``@admin_required``.
"""

from __future__ import annotations

from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.models import Group
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from access.models import AdvisoryAccessGrant, PendingInvitation, PrincipalType
from accounts.models import User
from accounts.services import ban_user, unban_user
from audit.models import Action
from audit.retention import forget_user
from audit.services import record_from_request
from common.net import client_ip
from projects.models import Project

from .base import admin_required

PER_PAGE = 50


@admin_required
def user_list(request):
    selected_q = (request.GET.get("q") or "").strip()[:200]
    selected_group_raw = (request.GET.get("group") or "").strip()
    selected_status = (request.GET.get("status") or "").strip()
    if selected_status not in ("active", "banned"):
        selected_status = ""

    qs = User.objects.prefetch_related("groups").order_by("email")

    if selected_q:
        qs = qs.filter(
            Q(email__icontains=selected_q)
            | Q(display_name__icontains=selected_q)
            | Q(first_name__icontains=selected_q)
            | Q(last_name__icontains=selected_q)
        )

    group_choices = list(Group.objects.order_by("name"))
    valid_group_ids = {g.pk for g in group_choices}
    selected_group = ""
    try:
        candidate = int(selected_group_raw)
    except (TypeError, ValueError):
        candidate = None
    if candidate is not None and candidate in valid_group_ids:
        qs = qs.filter(groups__pk=candidate).distinct()
        selected_group = str(candidate)

    # Ban status filters on the indexed ``banned_at`` column (``is_banned`` is a
    # Python-only property and not queryable).
    if selected_status == "banned":
        qs = qs.filter(banned_at__isnull=False)
    elif selected_status == "active":
        qs = qs.filter(banned_at__isnull=True)

    page = Paginator(qs, PER_PAGE).get_page(request.GET.get("page"))

    filters_pairs: list[tuple[str, str]] = []
    if selected_q:
        filters_pairs.append(("q", selected_q))
    if selected_group:
        filters_pairs.append(("group", selected_group))
    if selected_status:
        filters_pairs.append(("status", selected_status))
    filters_querystring = urlencode(filters_pairs)

    return render(
        request,
        "admin_console/user_list.html",
        {
            "page": page,
            "selected_q": selected_q,
            "selected_group": selected_group,
            "selected_status": selected_status,
            "group_choices": group_choices,
            "filters_querystring": filters_querystring,
            "any_filter_active": bool(selected_q or selected_group or selected_status),
            "admin_section": "users",
        },
    )


@admin_required
def user_detail(request, user_id: int):
    target_user = get_object_or_404(User, pk=user_id)

    groups = list(target_user.groups.order_by("name"))
    user_group_ids = [g.pk for g in groups]
    group_by_pk = {g.pk: g for g in groups}

    is_admin = any(g.name == settings.OIDC_ADMIN_GROUP for g in groups)

    secured_projects = list(
        Project.objects.filter(security_team_id__in=user_group_ids)
        .select_related("security_team")
        .order_by("name")
    )

    direct_grants = list(
        AdvisoryAccessGrant.objects.filter(
            principal_type=PrincipalType.USER, principal_id=target_user.pk
        )
        .select_related("advisory", "advisory__project")
        .order_by("advisory__advisory_id")
    )

    inherited_qs = (
        AdvisoryAccessGrant.objects.filter(
            principal_type=PrincipalType.GROUP, principal_id__in=user_group_ids
        )
        .select_related("advisory", "advisory__project")
        .order_by("advisory__advisory_id")
    )
    inherited_buckets: dict[int, list[AdvisoryAccessGrant]] = {}
    for grant in inherited_qs:
        inherited_buckets.setdefault(grant.principal_id, []).append(grant)
    inherited_groups = [
        {"group": group_by_pk[pk], "grants": inherited_buckets[pk]}
        for pk in sorted(inherited_buckets, key=lambda k: group_by_pk[k].name)
    ]

    pending_invitations = list(
        PendingInvitation.objects.filter(email__iexact=target_user.email, redeemed_at__isnull=True)
        .select_related("advisory", "advisory__project")
        .order_by("expires_at")
    )

    global_prefs = getattr(target_user, "notification_preferences", None)
    advisory_pref_overrides_qs = target_user.advisory_notification_preferences.select_related(
        "advisory"
    ).order_by("advisory__advisory_id")
    advisory_pref_overrides_count = advisory_pref_overrides_qs.count()
    advisory_pref_overrides_preview = list(advisory_pref_overrides_qs[:10])

    return render(
        request,
        "admin_console/user_detail.html",
        {
            "target_user": target_user,
            "is_admin": is_admin,
            "is_self": target_user.pk == request.user.pk,
            "groups": groups,
            "secured_projects": secured_projects,
            "direct_grants": direct_grants,
            "inherited_groups": inherited_groups,
            "pending_invitations": pending_invitations,
            "global_prefs": global_prefs,
            "advisory_pref_overrides_count": advisory_pref_overrides_count,
            "advisory_pref_overrides_preview": advisory_pref_overrides_preview,
            "admin_section": "users",
        },
    )


@admin_required
@require_http_methods(["POST"])
def user_ban(request, user_id: int):
    """Ban a user account: disable sign-in and drop any live session.

    An admin may ban anyone *except themselves* (the self-ban guard prevents an
    accidental lockout); banning another global admin is allowed as an
    emergency override. A reason is required. See INV-AUTH-8.
    """
    target = get_object_or_404(User, pk=user_id)
    back = redirect(reverse("admin_console:user_detail", args=[target.pk]))

    if target.pk == request.user.pk:
        messages.error(request, "You cannot ban your own account.")
        return back

    reason = (request.POST.get("reason") or "").strip()
    if not reason:
        messages.error(request, "A reason is required to ban an account.")
        return back

    if not ban_user(target, by=request.user, reason=reason):
        messages.info(request, f"{target.email} is already banned.")
        return back

    record_from_request(
        request,
        action=Action.USER_BANNED,
        metadata={
            "target_user_id": target.pk,
            "target_email": target.email,
            "reason": reason,
        },
    )
    messages.success(request, f"{target.email} has been banned and signed out.")
    return back


@admin_required
@require_http_methods(["POST"])
def user_unban(request, user_id: int):
    """Lift a ban: restore sign-in and notifications for the account."""
    target = get_object_or_404(User, pk=user_id)
    back = redirect(reverse("admin_console:user_detail", args=[target.pk]))

    previous_reason = unban_user(target, by=request.user)
    if previous_reason is None:
        messages.info(request, f"{target.email} is not banned.")
        return back

    record_from_request(
        request,
        action=Action.USER_UNBANNED,
        metadata={
            "target_user_id": target.pk,
            "target_email": target.email,
            "previous_reason": previous_reason,
        },
    )
    messages.success(request, f"{target.email} has been unbanned.")
    return back


@admin_required
@require_http_methods(["POST"])
def user_forget(request, user_id: int):
    """Exercise a GDPR right-to-be-forgotten against ``user_id``.

    Permanently anonymizes the account and scrubs the user's PII across the
    system (audit JSON, comments + edit history, invitations, intake sidecars,
    roster) via :func:`audit.retention.forget_user`. The audit record of the
    erasure itself is kept. Admin-only (``@admin_required``), never against
    oneself, and double-guarded against accidents: a justification message is
    required *and* the admin must retype the user's email to confirm (the
    submit button is gated client-side, re-checked here).
    """
    target = get_object_or_404(User, pk=user_id)
    back = redirect(reverse("admin_console:user_detail", args=[target.pk]))

    if target.pk == request.user.pk:
        messages.error(request, "You cannot forget your own account.")
        return back

    reason = (request.POST.get("reason") or "").strip()
    if not reason:
        messages.error(request, "A justification message is required to forget an account.")
        return back

    confirm = (request.POST.get("confirm_email") or "").strip().lower()
    if confirm != (target.email or "").strip().lower():
        messages.error(request, "The confirmation email did not match.")
        return back

    original_email = target.email
    forget_user(
        target,
        by=request.user,
        reason=reason,
        ip_address=client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
    )
    messages.success(request, f"{original_email} has been forgotten and anonymized.")
    return back
