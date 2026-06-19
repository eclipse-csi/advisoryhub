"""Inbox — admin console home page.

Shows a counts strip and a single unified chronological action list
merging open CVE requests, pending reviews, advisories needing a
(re-)publish run (failed exports + edited-since-publish), pending
triage advisories, and orphan CVEs.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from itertools import chain

from django.core.paginator import Paginator
from django.shortcuts import render
from django.urls import reverse

from advisories.models import Advisory, Kind, State
from publication.models import PublicationTask, PublicationTaskStatus
from workflows.models import (
    CveRequestStatus,
    CveRequestTask,
    OrphanCve,
    OrphanCveReassignmentStatus,
    OrphanCveReassignmentTask,
    OrphanCveStatus,
    ReviewTask,
    ReviewTaskStatus,
)

from .base import admin_required

# Generous safety cap on rows pulled per source before the merged sort.
# Five sources × 500 = 2,500 candidate rows, sorted in-process; trivial.
# Beyond this the in-memory paginator's last-page count can drift, but
# the inbox is meant to surface *open* work — backlogs that deep belong
# in the per-section pages.
PER_SOURCE_LIMIT = 500
INBOX_PER_PAGE = 25


@dataclass(frozen=True)
class InboxItem:
    kind: str
    badge: str
    badge_class: str
    title: str
    subtitle: str
    age_dt: datetime
    url: str
    see_more_url: str


# Maps the `?category=<slug>` value to a predicate on InboxItem.
# `triage_routing` is the routing-flagged subset of kind="triage".
# `needs_publish` ("publish required") spans two kinds with the same outcome —
# a publish run must happen again: failed exports (kind="pub_failed") and
# advisories edited since their last successful publish (kind="republish").
CATEGORY_PREDICATES: dict[str, Callable[[InboxItem], bool]] = {
    "cve": lambda i: i.kind == "cve",
    "review": lambda i: i.kind == "review",
    "needs_publish": lambda i: i.kind in ("pub_failed", "republish"),
    "triage": lambda i: i.kind == "triage",
    "triage_routing": lambda i: (
        i.kind == "triage" and i.badge_class == "inbox-badge--triage-routing"
    ),
    "orphan": lambda i: i.kind == "orphan",
    "reassignment": lambda i: i.kind == "reassignment",
    "withdrawal": lambda i: i.kind == "withdrawal",
}

# A few `show_more` slugs span more than one InboxItem kind. `rendered_per_kind`
# is keyed by kind, so the "remaining" math must sum across every kind a slug
# covers. Slugs absent here map 1:1 to a kind of the same name.
SLUG_KINDS: dict[str, tuple[str, ...]] = {
    "needs_publish": ("pub_failed", "republish"),
}


def _truncate(s: str | None, n: int = 80) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[: n - 1] + "…"


def _reporter_label(advisory: Advisory) -> str:
    intake = getattr(advisory, "intake", None)
    if intake is None:
        return ""
    if intake.reporter_user_id:
        return intake.reporter_user.email
    return intake.reporter_display_name or "anonymous"


def _cve_items(see_more_url: str) -> list[InboxItem]:
    qs = (
        CveRequestTask.objects.filter(status=CveRequestStatus.QUEUED)
        .select_related("advisory", "advisory__project")
        .order_by("-created_at")[:PER_SOURCE_LIMIT]
    )
    return [
        InboxItem(
            kind="cve",
            badge="CVE",
            badge_class="inbox-badge--cve",
            title=t.advisory.advisory_id,
            subtitle=t.advisory.project.slug,
            age_dt=t.created_at,
            # CVE assignment is admin-only and happens on the CVE queue, not on
            # the advisory detail page — deep-link straight to this task's row.
            url=f"{see_more_url}#cve-task-{t.pk}",
            see_more_url=see_more_url,
        )
        for t in qs
    ]


def _review_items(see_more_url: str) -> list[InboxItem]:
    qs = (
        ReviewTask.objects.filter(status=ReviewTaskStatus.OPEN)
        .select_related("advisory", "advisory__project", "submitted_by")
        .order_by("-created_at")[:PER_SOURCE_LIMIT]
    )
    return [
        InboxItem(
            kind="review",
            badge="Review",
            badge_class="inbox-badge--review",
            title=t.advisory.advisory_id,
            subtitle=f"submitted by {t.submitted_by.email}"
            if t.submitted_by
            else t.advisory.project.slug,
            age_dt=t.created_at,
            url=reverse("advisories:detail", args=[t.advisory.advisory_id]),
            see_more_url=see_more_url,
        )
        for t in qs
    ]


def _publication_items(see_more_url: str) -> list[InboxItem]:
    qs = (
        PublicationTask.objects.filter(status=PublicationTaskStatus.FAILED)
        .select_related("advisory")
        .order_by("-finished_at", "-created_at")[:PER_SOURCE_LIMIT]
    )
    return [
        InboxItem(
            kind="pub_failed",
            badge="Publish",
            badge_class="inbox-badge--pub",
            title=t.advisory.advisory_id,
            subtitle=_truncate(t.last_error, 80),
            age_dt=t.finished_at or t.created_at,
            # Retry of a failed export lives on the publication queue, not on
            # the advisory detail page — deep-link straight to this task's row.
            url=f"{see_more_url}#pub-task-{t.pk}",
            see_more_url=see_more_url,
        )
        for t in qs
    ]


def _republish_items(see_more_url: str, failed_advisory_ids: set[int]) -> list[InboxItem]:
    # Published advisories edited since their last successful publish. Same
    # outcome as a failed export — a publish run must happen again — so they
    # share the "publish required" category.
    #
    # GHSA-linked rows auto-re-publish with no human action (INV-GHSA-3), so
    # they are excluded here, mirroring _triage_items; a GHSA-linked advisory
    # whose auto-republish *fails* still surfaces via _publication_items.
    #
    # Dedup: an advisory whose re-publish already failed carries both a FAILED
    # PublicationTask and republish_required=True. The failed-task row wins (it
    # has the redacted error + Retry button), so drop it from this source.
    qs = (
        Advisory.objects.filter(state=State.PUBLISHED, republish_required=True)
        .exclude(kind=Kind.GHSA_LINKED)
        .exclude(pk__in=failed_advisory_ids)
        .select_related("project")
        .order_by("-modified_at")[:PER_SOURCE_LIMIT]
    )
    return [
        InboxItem(
            kind="republish",
            badge="Publish",
            badge_class="inbox-badge--pub",
            title=a.advisory_id,
            subtitle=f"edited since publish · {a.project.slug}",
            age_dt=a.modified_at,
            # No retry row exists for these — the Re-publish button lives on the
            # advisory detail sidebar, so deep-link straight to the advisory.
            url=reverse("advisories:detail", args=[a.advisory_id]),
            see_more_url=see_more_url,
        )
        for a in qs
    ]


def _triage_items(see_more_url: str) -> list[InboxItem]:
    # GHSA-linked triage rows are a read-only mirror of GitHub's triage state
    # (INV-GHSA-3) — they advance automatically and carry no human action, so
    # they stay out of the actionable inbox (they still show in the advisory
    # list's triage tab).
    qs = (
        Advisory.objects.filter(state=State.TRIAGE)
        .exclude(kind=Kind.GHSA_LINKED)
        .select_related("project", "intake", "intake__reporter_user")
        .order_by("-created_at")[:PER_SOURCE_LIMIT]
    )
    items: list[InboxItem] = []
    for a in qs:
        intake = getattr(a, "intake", None)
        if intake is not None and intake.needs_admin_routing:
            note = _truncate(intake.admin_routing_note, 70)
            subtitle = f"{a.project.slug} · {note}" if note else a.project.slug
            badge = "Routing"
            badge_class = "inbox-badge--triage-routing"
        else:
            subtitle = _reporter_label(a) or a.project.slug
            badge = "Triage"
            badge_class = "inbox-badge--triage"
        items.append(
            InboxItem(
                kind="triage",
                badge=badge,
                badge_class=badge_class,
                title=_truncate(a.summary or a.advisory_id, 80),
                subtitle=subtitle,
                age_dt=a.created_at,
                url=reverse("advisories:detail", args=[a.advisory_id]),
                see_more_url=see_more_url,
            )
        )
    return items


def _orphan_items(see_more_url: str) -> list[InboxItem]:
    qs = (
        OrphanCve.objects.filter(status=OrphanCveStatus.ORPHANED)
        .select_related("previous_advisory")
        .order_by("-unassigned_at")[:PER_SOURCE_LIMIT]
    )
    return [
        InboxItem(
            kind="orphan",
            badge="Orphan",
            badge_class="inbox-badge--orphan",
            title=o.cve_id,
            subtitle=o.previous_advisory_label or "(advisory deleted)",
            age_dt=o.unassigned_at,
            url=see_more_url,
            see_more_url=see_more_url,
        )
        for o in qs
    ]


def _reassignment_items(see_more_url: str) -> list[InboxItem]:
    qs = (
        OrphanCveReassignmentTask.objects.filter(status=OrphanCveReassignmentStatus.QUEUED)
        .select_related("advisory", "orphan_cve")
        .order_by("-created_at")[:PER_SOURCE_LIMIT]
    )
    return [
        InboxItem(
            kind="reassignment",
            badge="Reassign",
            badge_class="inbox-badge--orphan",
            title=t.orphan_cve.cve_id,
            subtitle=f"reopened: {t.advisory.advisory_id}",
            age_dt=t.created_at,
            url=see_more_url,
            see_more_url=see_more_url,
        )
        for t in qs
    ]


def _withdrawal_items() -> list[InboxItem]:
    qs = (
        Advisory.objects.filter(withdrawal_requested_at__isnull=False)
        .select_related("project")
        .order_by("-withdrawal_requested_at")[:PER_SOURCE_LIMIT]
    )
    items: list[InboxItem] = []
    for a in qs:
        # Non-null by the isnull=False filter above; narrow for the type checker
        # (the field is a nullable DateTimeField, so it is typed datetime | None).
        requested_at = a.withdrawal_requested_at
        if requested_at is None:
            continue
        items.append(
            InboxItem(
                kind="withdrawal",
                badge="Withdraw",
                badge_class="inbox-badge--pub",
                title=a.advisory_id,
                subtitle=f"withdrawal requested: {a.project.slug}",
                age_dt=requested_at,
                url=reverse("advisories:detail", args=[a.advisory_id]),
                see_more_url=reverse("advisories:detail", args=[a.advisory_id]),
            )
        )
    return items


@admin_required
def inbox(request):
    cves_url = reverse("admin_console:cves")
    publications_url = reverse("admin_console:publications")

    # Advisories with a failed export are surfaced by _publication_items; keep
    # them out of _republish_items so a failed re-publish appears exactly once.
    failed_advisory_ids = set(
        PublicationTask.objects.filter(status=PublicationTaskStatus.FAILED).values_list(
            "advisory_id", flat=True
        )
    )

    all_items = list(
        chain(
            _cve_items(cves_url),
            _review_items(""),
            _publication_items(publications_url),
            _republish_items(publications_url, failed_advisory_ids),
            _triage_items(""),
            _orphan_items(cves_url),
            _reassignment_items(cves_url),
            _withdrawal_items(),
        )
    )
    all_items.sort(key=lambda i: i.age_dt, reverse=True)

    requested_category = request.GET.get("category") or ""
    selected_category = requested_category if requested_category in CATEGORY_PREDICATES else ""
    if selected_category:
        predicate = CATEGORY_PREDICATES[selected_category]
        all_items = [i for i in all_items if predicate(i)]

    page = Paginator(all_items, INBOX_PER_PAGE).get_page(request.GET.get("page"))

    counts = {
        "cve_open": CveRequestTask.objects.filter(status=CveRequestStatus.QUEUED).count(),
        "review_open": ReviewTask.objects.filter(status=ReviewTaskStatus.OPEN).count(),
        # "publish required" combines failed exports and republish-required
        # advisories (deduped, GHSA-linked excluded — see _republish_items).
        "needs_publish": (
            PublicationTask.objects.filter(status=PublicationTaskStatus.FAILED).count()
            + Advisory.objects.filter(state=State.PUBLISHED, republish_required=True)
            .exclude(kind=Kind.GHSA_LINKED)
            .exclude(pk__in=failed_advisory_ids)
            .count()
        ),
        "triage": Advisory.objects.filter(state=State.TRIAGE)
        .exclude(kind=Kind.GHSA_LINKED)
        .count(),
        "triage_routing": Advisory.objects.filter(
            state=State.TRIAGE, intake__needs_admin_routing=True
        ).count(),
        "orphan": OrphanCve.objects.filter(status=OrphanCveStatus.ORPHANED).count(),
        "reassignment": OrphanCveReassignmentTask.objects.filter(
            status=OrphanCveReassignmentStatus.QUEUED
        ).count(),
        "withdrawal": Advisory.objects.filter(withdrawal_requested_at__isnull=False).count(),
    }

    rendered_per_kind: dict[str, int] = {}
    for item in page.object_list:
        rendered_per_kind[item.kind] = rendered_per_kind.get(item.kind, 0) + 1

    # "Jump to section page" strip. Triage no longer has its own section page;
    # the inbox + chip filter handle the triage queue now.
    all_show_more_entries = (
        # (slug, counts_key, label, url_name)
        ("cve", "cve_open", "CVE requests", "cves"),
        ("needs_publish", "needs_publish", "Publish required", "publications"),
        ("orphan", "orphan", "Orphan CVEs", "cves"),
        ("reassignment", "reassignment", "CVE reassignments", "cves"),
    )
    if selected_category:
        candidate_entries = tuple(e for e in all_show_more_entries if e[0] == selected_category)
    else:
        candidate_entries = all_show_more_entries

    show_more = []
    for slug, counts_key, label, url_name in candidate_entries:
        if selected_category:
            rendered = len(page.object_list)
        else:
            # A slug may span several kinds (e.g. needs_publish); sum across all.
            rendered = sum(rendered_per_kind.get(k, 0) for k in SLUG_KINDS.get(slug, (slug,)))
        remaining = counts[counts_key] - rendered
        if remaining > 0:
            show_more.append(
                {
                    "kind": slug,
                    "label": label,
                    "remaining": remaining,
                    "url": reverse(f"admin_console:{url_name}"),
                }
            )

    return render(
        request,
        "admin_console/inbox.html",
        {
            "page": page,
            "counts": counts,
            "show_more": show_more,
            "selected_category": selected_category,
            "admin_section": "inbox",
        },
    )
