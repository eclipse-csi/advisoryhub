"""Publication queue — open + failed + awaiting re-publication + recently published."""

from __future__ import annotations

from django.shortcuts import render

from advisories.models import Advisory, Kind, State
from publication.models import PublicationTask, PublicationTaskStatus

from .base import admin_required


@admin_required
def publications(request):
    open_publications = list(
        PublicationTask.objects.filter(
            status__in=[PublicationTaskStatus.QUEUED, PublicationTaskStatus.RUNNING]
        )
        .select_related("advisory")
        .order_by("created_at")
    )
    failed_publications = list(
        PublicationTask.objects.filter(status=PublicationTaskStatus.FAILED)
        .select_related("advisory", "enqueued_by")
        .prefetch_related("artifacts")
        .order_by("-finished_at", "-created_at")[:50]
    )
    # Published advisories edited since their last successful publish. Same
    # outcome as a failed export — a publish run must happen again. GHSA-linked
    # rows auto-re-publish (INV-GHSA-3) and are excluded; an advisory already
    # listed under failed exports is deduped out (the failed row carries the
    # actionable error + Retry).
    failed_advisory_ids = set(
        PublicationTask.objects.filter(status=PublicationTaskStatus.FAILED).values_list(
            "advisory_id", flat=True
        )
    )
    awaiting_republish = list(
        Advisory.objects.filter(state=State.PUBLISHED, republish_required=True)
        .exclude(kind=Kind.GHSA_LINKED)
        .exclude(pk__in=failed_advisory_ids)
        .select_related("project")
        .order_by("-modified_at")[:50]
    )
    recently_published = list(
        Advisory.objects.filter(state=State.PUBLISHED).order_by("-published_at", "-modified_at")[
            :25
        ]
    )
    return render(
        request,
        "admin_console/publications.html",
        {
            "open_publications": open_publications,
            "failed_publications": failed_publications,
            "awaiting_republish": awaiting_republish,
            "recently_published": recently_published,
            "admin_section": "publications",
        },
    )
