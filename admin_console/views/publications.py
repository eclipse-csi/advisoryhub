"""Publication queue — open + failed + recently published."""

from __future__ import annotations

from django.shortcuts import render

from advisories.models import Advisory, State
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
            "recently_published": recently_published,
            "admin_section": "publications",
        },
    )
