"""Projects & OIDC groups CRUD for the admin console."""

from __future__ import annotations

from django.contrib import messages
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

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
        {"form": form, "project": project},
    )
