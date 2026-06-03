"""Projects & OIDC groups CRUD for the admin console."""

from __future__ import annotations

from django.conf import settings
from django.contrib import messages
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from common.ratelimit import html_ratelimit
from projects.forms import ProjectAdminForm
from projects.models import Project

from .base import admin_required


@admin_required
def project_list(request):
    projects = (
        Project.objects.select_related("security_team")
        .annotate(advisory_count=Count("advisories"))
        .order_by("name")
    )
    return render(request, "admin_console/project_list.html", {"projects": projects})


@admin_required
def project_create(request):
    if request.method == "POST":
        form = ProjectAdminForm(request.POST)
        if form.is_valid():
            project = form.save()
            messages.success(request, f"Project {project.slug} created.")
            return redirect(reverse("admin_console:project_list"))
    else:
        form = ProjectAdminForm()
    return render(
        request,
        "admin_console/project_form.html",
        {"form": form, "project": None},
    )


@admin_required
def project_edit(request, project_id):
    project = get_object_or_404(Project, pk=project_id)
    if request.method == "POST":
        form = ProjectAdminForm(request.POST, instance=project)
        if form.is_valid():
            form.save()
            messages.success(request, f"Project {project.slug} updated.")
            return redirect(reverse("admin_console:project_list"))
    else:
        form = ProjectAdminForm(instance=project)
    return render(
        request,
        "admin_console/project_form.html",
        {
            "form": form,
            "project": project,
            "roster_sync_enabled": getattr(settings, "PMI_ROSTER_SYNC_ENABLED", False),
            "active_roster_count": project.security_roster.filter(
                soft_removed_at__isnull=True
            ).count(),
        },
    )


@admin_required
@require_http_methods(["POST"])
@html_ratelimit(rate="10/h")
def project_sync_roster(request, project_id):
    """Manually refresh a project's security-team roster from the Eclipse API.

    Runs inline (like the PMI repo refresh) so the operator sees the result
    immediately. Gated on ``PMI_ROSTER_SYNC_ENABLED`` — the scheduled beat task
    does the bulk/cold-start work; this button is a manual refresh. Provisions
    notification-only shadow users; it grants no in-app access (INV-OIDC-5).
    """
    from projects import services
    from projects.eclipse_api import EclipseApiError

    project = get_object_or_404(Project, pk=project_id)
    if not getattr(settings, "PMI_ROSTER_SYNC_ENABLED", False):
        messages.error(request, "Security-team roster sync is not enabled.")
        return redirect("admin_console:project_edit", project_id=project.pk)
    try:
        active = services.sync_security_team_roster(project, by=request.user)
        messages.success(request, f"Security-team roster refreshed — {active} active member(s).")
    except EclipseApiError as exc:
        messages.error(request, f"Roster sync failed: {exc}")
    return redirect("admin_console:project_edit", project_id=project.pk)
