"""Cross-advisory invitation management for the admin console.

Pending invitations are otherwise only reachable from each advisory's access
panel. This section lists every outstanding (non-redeemed) invitation across
all advisories and lets an admin re-send or cancel one.

``@admin_required`` enforces INV-AUTH-1; all mutation goes through
``access.services`` so the audit trail (INV-ACCESS-5) and email dispatch stay
in the service layer.
"""

from __future__ import annotations

from urllib.parse import urlencode

from django.contrib import messages
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from access import services
from access.models import PendingInvitation
from projects.models import Project

from .base import admin_required

PER_PAGE = 50

_VALID_STATUSES = ("pending", "expired")


@admin_required
def invitation_list(request):
    now = timezone.now()

    selected_q = (request.GET.get("q") or "").strip()[:200]
    selected_project_raw = (request.GET.get("project") or "").strip()
    selected_status = (request.GET.get("status") or "").strip()
    if selected_status not in _VALID_STATUSES:
        selected_status = ""

    qs = (
        PendingInvitation.objects.filter(redeemed_at__isnull=True)
        .select_related("advisory", "advisory__project", "created_by")
        .order_by("expires_at")
    )

    if selected_q:
        qs = qs.filter(email__icontains=selected_q)

    project_choices = list(Project.objects.order_by("name"))
    valid_project_ids = {str(p.pk) for p in project_choices}
    selected_project = ""
    if selected_project_raw in valid_project_ids:
        qs = qs.filter(advisory__project_id=selected_project_raw)
        selected_project = selected_project_raw

    if selected_status == "pending":
        qs = qs.filter(expires_at__gt=now)
    elif selected_status == "expired":
        qs = qs.filter(expires_at__lte=now)

    page = Paginator(qs, PER_PAGE).get_page(request.GET.get("page"))

    filters_pairs: list[tuple[str, str]] = []
    if selected_q:
        filters_pairs.append(("q", selected_q))
    if selected_project:
        filters_pairs.append(("project", selected_project))
    if selected_status:
        filters_pairs.append(("status", selected_status))
    filters_querystring = urlencode(filters_pairs)

    return render(
        request,
        "admin_console/invitation_list.html",
        {
            "page": page,
            "now": now,
            "selected_q": selected_q,
            "selected_project": selected_project,
            "selected_status": selected_status,
            "project_choices": project_choices,
            "filters_querystring": filters_querystring,
            "any_filter_active": bool(selected_q or selected_project or selected_status),
            "admin_section": "invitations",
        },
    )


def _back_to_list(request):
    """Redirect to the list, preserving the filter state echoed in the POST."""
    pairs: list[tuple[str, str]] = []
    for key in ("q", "project", "status", "page"):
        value = (request.POST.get(key) or "").strip()
        if value:
            pairs.append((key, value))
    url = reverse("admin_console:invitation_list")
    if pairs:
        url = f"{url}?{urlencode(pairs)}"
    return redirect(url)


@admin_required
@require_http_methods(["POST"])
def invitation_resend(request, invitation_id: int):
    invitation = get_object_or_404(PendingInvitation, pk=invitation_id)
    if invitation.redeemed_at is not None:
        messages.info(request, f"The invitation to {invitation.email} has already been redeemed.")
        return _back_to_list(request)
    services.resend_invitation(invitation, by=request.user)
    messages.success(
        request,
        f"Invitation to {invitation.email} re-sent; it is valid again for 14 days.",
    )
    return _back_to_list(request)


@admin_required
@require_http_methods(["POST"])
def invitation_revoke(request, invitation_id: int):
    invitation = get_object_or_404(PendingInvitation, pk=invitation_id)
    email = invitation.email
    services.revoke_invitation(invitation, by=request.user)
    messages.success(request, f"Invitation to {email} cancelled.")
    return _back_to_list(request)
