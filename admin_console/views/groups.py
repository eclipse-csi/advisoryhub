"""Read-only Groups directory for the admin console.

Lists Django ``Group`` rows mirrored from OIDC claims, with each group's
membership, the projects it secures, and the per-advisory grants attached
to it. Read-only; INV-AUTH-1 is enforced by ``@admin_required``.
"""

from __future__ import annotations

from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.models import Group
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, render

from access.models import AdvisoryAccessGrant, PrincipalType

from .base import admin_required
from .users import PER_PAGE


@admin_required
def group_list(request):
    selected_q = (request.GET.get("q") or "").strip()[:200]

    qs = Group.objects.order_by("name")
    if selected_q:
        qs = qs.filter(name__icontains=selected_q)

    # Annotate counts after filtering. ``user`` is the default reverse name
    # for ``AbstractUser.groups``; ``projects_secured`` is the related_name
    # on ``Project.security_team``.
    from django.db.models import Count

    qs = qs.annotate(
        member_count=Count("user", distinct=True),
        projects_secured_count=Count("projects_secured", distinct=True),
    )

    page = Paginator(qs, PER_PAGE).get_page(request.GET.get("page"))

    filters_pairs: list[tuple[str, str]] = []
    if selected_q:
        filters_pairs.append(("q", selected_q))
    filters_querystring = urlencode(filters_pairs)

    return render(
        request,
        "admin_console/group_list.html",
        {
            "page": page,
            "selected_q": selected_q,
            "filters_querystring": filters_querystring,
            "any_filter_active": bool(selected_q),
            "admin_group_name": settings.OIDC_ADMIN_GROUP,
            "admin_section": "groups",
        },
    )


@admin_required
def group_detail(request, group_id: int):
    group = get_object_or_404(Group, pk=group_id)

    members = list(group.user_set.order_by("email"))
    secured_projects = list(group.projects_secured.order_by("name"))
    group_grants = list(
        AdvisoryAccessGrant.objects.filter(
            principal_type=PrincipalType.GROUP, principal_id=group.pk
        )
        .select_related("advisory", "advisory__project")
        .order_by("advisory__advisory_id")
    )

    return render(
        request,
        "admin_console/group_detail.html",
        {
            "group": group,
            "is_admin_group": group.name == settings.OIDC_ADMIN_GROUP,
            "members": members,
            "secured_projects": secured_projects,
            "group_grants": group_grants,
            "admin_section": "groups",
        },
    )
