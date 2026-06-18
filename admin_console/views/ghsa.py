"""GHSA operations & observability — Admin Console section.

A read-only dashboard that surfaces the GHSA integration's bookkeeping
tables (failed CVE pushes, recent sync runs, recent webhook deliveries,
registered installations) and offers the operator the maintenance actions
that already live in :mod:`ghsa.views` (sync-all, PMI refresh, reconcile,
discovery, rescan installations, retry CVE pushes, webhook catch-up).

This view only displays; every action button POSTs to a ``ghsa:`` endpoint
that re-affirms authorization, step-up, and rate limits server-side
(``INV-AUTH-1``). The GitHub-App *configuration* page stays separate at
``ghsa:connect`` and is reached via a link here.
"""

from __future__ import annotations

from django.conf import settings
from django.shortcuts import render

from ghsa.models import (
    GhsaCvePushTask,
    GhsaCvePushTaskStatus,
    GhsaSyncRun,
    GitHubAppInstallation,
    WebhookDelivery,
)

from .base import admin_required

# Generous display caps — these are observability tables, not work queues;
# deep history lives in the audit log.
FAILED_PUSH_LIMIT = 50
SYNC_RUN_LIMIT = 25
WEBHOOK_LIMIT = 25


@admin_required
def ghsa_dashboard(request):
    feature_enabled = getattr(settings, "GHSA_FEATURE_ENABLED", False)

    failed_cve_pushes = list(
        GhsaCvePushTask.objects.filter(status=GhsaCvePushTaskStatus.FAILED)
        .select_related("advisory")
        .order_by("-created_at")[:FAILED_PUSH_LIMIT]
    )
    sync_runs = list(
        GhsaSyncRun.objects.select_related("project", "advisory", "requested_by").order_by(
            "-started_at"
        )[:SYNC_RUN_LIMIT]
    )
    webhook_deliveries = list(WebhookDelivery.objects.order_by("-received_at")[:WEBHOOK_LIMIT])
    installations = list(GitHubAppInstallation.objects.all().order_by("account_login"))

    return render(
        request,
        "admin_console/ghsa.html",
        {
            "admin_section": "ghsa",
            "feature_enabled": feature_enabled,
            "failed_cve_pushes": failed_cve_pushes,
            "sync_runs": sync_runs,
            "webhook_deliveries": webhook_deliveries,
            "installations": installations,
        },
    )
