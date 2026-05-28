"""HTML views for the GHSA integration.

Every endpoint reaffirms authorization through ``advisories.permissions``;
templates only display. State-changing endpoints are also rate-limited and
the most sensitive ones (App config, org-wide sync, retry CVE push)
additionally require step-up reauthentication.
"""

from __future__ import annotations

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from accounts.step_up import require_step_up_or_redirect
from advisories import permissions as perms
from advisories.models import Advisory, Kind
from common.ratelimit import html_ratelimit
from projects.models import Project

from . import services
from .client import GitHubApiError
from .models import GhsaCvePushTask, GhsaCvePushTaskStatus, GitHubAppInstallation
from .pmi import PmiApiError
from .tasks import (
    run_cve_push,
    run_ghsa_sync_all,
    run_ghsa_sync_project,
    run_single_ghsa_sync,
)

# ---------------------------------------------------------------------------
# Admin: GitHub App config landing
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["GET"])
def connect_github_app(request):
    if not perms.can_configure_github_app(request.user):
        raise PermissionDenied("Only global admins can configure the GitHub App.")
    redirect_resp = require_step_up_or_redirect(request, next_url=request.path)
    if redirect_resp:
        return redirect_resp
    installations = list(GitHubAppInstallation.objects.all().order_by("account_login"))
    return render(
        request,
        "ghsa/connect.html",
        {
            "feature_enabled": getattr(settings, "GHSA_FEATURE_ENABLED", False),
            "app_id": getattr(settings, "GITHUB_APP_ID", 0),
            "api_base_url": getattr(settings, "GITHUB_APP_API_BASE_URL", ""),
            "has_private_key": bool(
                getattr(settings, "GITHUB_APP_PRIVATE_KEY_PATH", "")
                or getattr(settings, "GITHUB_APP_PRIVATE_KEY", "")
            ),
            "has_webhook_secret": bool(getattr(settings, "GITHUB_APP_WEBHOOK_SECRET", "")),
            "installations": installations,
        },
    )


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="5/h")
def rescan_installations(request):
    """Admin-only "Rescan installations" action — pulls /app/installations.

    Used as the cold-start path or as a backstop when webhook deliveries
    were missed. Step-up gated because it produces audit entries
    attributed to the admin user.
    """
    if not perms.can_configure_github_app(request.user):
        raise PermissionDenied("Only global admins can rescan installations.")
    redirect_resp = require_step_up_or_redirect(request, next_url=reverse("ghsa:connect"))
    if redirect_resp:
        return redirect_resp
    try:
        rows = services.discover_installations(by=request.user)
        messages.success(
            request,
            f"Rescan complete — {len(rows)} installation(s) registered.",
        )
    except GitHubApiError as exc:
        messages.error(request, f"GitHub /app/installations call failed: {exc}")
    return redirect("ghsa:connect")


# ---------------------------------------------------------------------------
# Project-scoped: refresh PMI repo mirror, sync GHSAs
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="10/h")
def sync_project_repos(request, project_id):
    project = get_object_or_404(Project, pk=project_id)
    if not perms.can_sync_project_ghsas(request.user, project):
        raise PermissionDenied("You cannot refresh PMI repos for this project.")
    try:
        active = services.sync_project_repos_from_pmi(project, by=request.user)
        messages.success(request, f"Refreshed PMI repo list — {active} active repo(s).")
    except PmiApiError as exc:
        messages.error(request, f"PMI sync failed: {exc}")
    return redirect("admin_console:project_edit", project_id=project.pk)


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="5/h")
def sync_project_ghsas(request, project_id):
    project = get_object_or_404(Project, pk=project_id)
    if not perms.can_sync_project_ghsas(request.user, project):
        raise PermissionDenied("You cannot sync GHSAs for this project.")
    if not getattr(settings, "GHSA_FEATURE_ENABLED", False):
        messages.error(request, "GHSA integration is not enabled.")
        return redirect("admin_console:project_edit", project_id=project.pk)
    # Run asynchronously when a broker is wired up; otherwise (e.g. dev with
    # CELERY_TASK_ALWAYS_EAGER) it executes inline and reports counters.
    try:
        result = run_ghsa_sync_project.delay(str(project.pk), getattr(request.user, "pk", None))
    except Exception:
        # Broker offline: fall back to inline so the operator still gets a
        # useful response. Mirrors the publication broker-offline behaviour.
        run = services.sync_ghsas_for_project(project, by=request.user)
        messages.success(
            request,
            f"GHSA sync (inline) finished: created {run.advisories_created}, "
            f"updated {run.advisories_updated}, errors {run.errors_count}.",
        )
        return redirect("admin_console:project_edit", project_id=project.pk)
    messages.success(request, f"GHSA sync queued (task id {result.id}).")
    return redirect("admin_console:project_edit", project_id=project.pk)


# ---------------------------------------------------------------------------
# Org-wide sync — admin only, step-up required
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="2/h")
def sync_all_ghsas(request):
    if not perms.can_sync_all_ghsas(request.user):
        raise PermissionDenied("Only global admins can sync all projects.")
    redirect_resp = require_step_up_or_redirect(request, next_url=reverse("admin_console:index"))
    if redirect_resp:
        return redirect_resp
    if not getattr(settings, "GHSA_FEATURE_ENABLED", False):
        messages.error(request, "GHSA integration is not enabled.")
        return redirect("admin_console:index")
    try:
        run_ghsa_sync_all.delay(getattr(request.user, "pk", None))
        messages.success(request, "Org-wide GHSA sync queued.")
    except Exception:
        run = services.sync_ghsas_for_all_projects(by=request.user)
        messages.success(
            request,
            f"Org-wide GHSA sync (inline) finished: created {run.advisories_created}, "
            f"updated {run.advisories_updated}, errors {run.errors_count}.",
        )
    return redirect("admin_console:index")


# ---------------------------------------------------------------------------
# Per-advisory: refresh from GHSA
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="30/h")
def refresh_advisory_ghsa(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if advisory.kind != Kind.GHSA_LINKED:
        raise PermissionDenied("This advisory is not GHSA-linked.")
    if not perms.can_sync_ghsa(request.user, advisory):
        raise PermissionDenied("You cannot refresh this advisory from GHSA.")
    try:
        # Run inline rather than async — owners expect to see the result
        # of "Refresh" land immediately, and one GitHub round-trip is
        # short enough to do in-request.
        result = services.sync_single_ghsa(advisory, by=request.user)
        if result.get("missing_upstream"):
            messages.warning(
                request, "Upstream GHSA could not be found on GitHub — marked as closed."
            )
        elif result["changed"]:
            messages.success(
                request,
                f"Refreshed from GHSA: updated {', '.join(result['changed'])}.",
            )
        else:
            messages.info(request, "No changes from GHSA.")
    except GitHubApiError as exc:
        messages.error(request, f"GitHub fetch failed: {exc}")
    return redirect("advisories:detail", advisory_id=advisory.advisory_id)


# ---------------------------------------------------------------------------
# Retry CVE push to GHSA — admin only, step-up required
# ---------------------------------------------------------------------------


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="10/h")
def retry_cve_push(request, task_id: int):
    if not perms.can_retry_cve_push(request.user):
        raise PermissionDenied("Only admins can retry CVE push tasks.")
    redirect_resp = require_step_up_or_redirect(request, next_url=reverse("admin_console:index"))
    if redirect_resp:
        return redirect_resp
    task = get_object_or_404(GhsaCvePushTask, pk=task_id)
    if task.status not in (GhsaCvePushTaskStatus.FAILED, GhsaCvePushTaskStatus.QUEUED):
        messages.error(request, "Only failed or queued push tasks can be retried.")
        return redirect("admin_console:index")
    task.status = GhsaCvePushTaskStatus.QUEUED
    task.last_error = ""
    task.save(update_fields=["status", "last_error"])
    try:
        run_cve_push.delay(task.pk)
        messages.success(request, f"CVE push task {task.pk} re-queued.")
    except Exception:
        services.push_reserved_cve_to_ghsa(task)
        messages.success(request, "CVE push retried inline (broker offline).")
    return redirect("admin_console:index")


# GHSA-linked advisories are created automatically by:
#   * the per-project sync action (button on the project page or
#     ``manage.py sync_ghsa --project <slug>``), which enumerates every
#     advisory in each PMI-mirrored repo;
#   * the ``repository_advisory.published`` webhook from GitHub, which
#     auto-creates a draft as soon as a GHSA appears upstream.
# A manual "link this GHSA by id" form used to live here; it was dropped
# because every case it covered was already covered by sync/webhook, and
# its PMI cross-check made it useless for the one case (off-mirror
# repos) where manual entry might have been valuable.


# Re-export the management-command-friendly helper.
__all__ = [
    "connect_github_app",
    "rescan_installations",
    "sync_project_repos",
    "sync_project_ghsas",
    "sync_all_ghsas",
    "refresh_advisory_ghsa",
    "retry_cve_push",
    "run_single_ghsa_sync",
]
