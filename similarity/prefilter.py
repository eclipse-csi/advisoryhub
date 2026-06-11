"""Postgres candidate retrieval for the duplicate-detection judge call.

Recall-oriented (the LLM judge does precision): three passes, merged in
priority order, deduped, capped at the configured limit.

1. Exact identifier intersection (aliases / assigned CVE / GHSA id) —
   force-included; ``aliases__contains`` is served by the existing
   ``adv_aliases_gin`` jsonb_path_ops index.
2. Affected-package-name overlap — force-included; jsonb containment of a
   partial element, project-scoped so the missing index doesn't matter.
3. Trigram text similarity over summary/details — fills the remaining slots,
   served by the existing ``adv_summary_trgm`` / ``adv_details_trgm`` GIN
   indexes (the ``pg_trgm`` extension ships with the initial migration).

Corpus is the advisory's own project only (a decided product constraint:
every owner-viewer of the new report is an owner on all same-project
matches, so results never need per-viewer filtering), across all lifecycle
states — duplicate reports frequently target dismissed or published flaws.
"""

from __future__ import annotations

from django.contrib.postgres.search import TrigramSimilarity
from django.db.models import Q
from django.db.models.functions import Greatest

from advisories.models import Advisory

from .llm import prompts

# Permissive on purpose: below this the text passes are mostly noise, above
# it we'd start dropping reworded duplicates. The judge call discards weak
# candidates anyway.
_TRIGRAM_FLOOR = 0.08
_DETAILS_NEEDLE_LIMIT = 1000


def candidate_advisories(advisory: Advisory, payload: dict, *, limit: int) -> list[Advisory]:
    """Up to ``limit`` same-project advisories worth showing to the judge."""
    base = Advisory.objects.filter(project_id=advisory.project_id).exclude(pk=advisory.pk)

    identifiers = prompts.payload_identifiers(payload)
    package_names = prompts.payload_package_names(payload)
    summary = (payload.get("summary") or "").strip()
    details_needle = (payload.get("details") or "").strip()[:_DETAILS_NEEDLE_LIMIT]

    id_hits: list[Advisory] = []
    if identifiers:
        id_q = Q()
        for ident in identifiers:
            id_q |= Q(aliases__contains=[ident]) | Q(assigned_cve_id=ident) | Q(ghsa_id=ident)
        id_hits = list(base.filter(id_q)[:limit])

    pkg_hits: list[Advisory] = []
    if package_names:
        pkg_q = Q()
        for name in package_names:
            pkg_q |= Q(affected__contains=[{"package": {"name": name}}])
        pkg_hits = list(base.filter(pkg_q)[:limit])

    text_hits: list[Advisory] = []
    if summary or details_needle:
        text_hits = list(
            base.annotate(
                sim=Greatest(
                    TrigramSimilarity("summary", summary or ""),
                    TrigramSimilarity("details", details_needle or ""),
                )
            )
            .filter(sim__gt=_TRIGRAM_FLOOR)
            .order_by("-sim")[:limit]
        )

    merged: list[Advisory] = []
    seen: set[int] = set()
    for candidate in (*id_hits, *pkg_hits, *text_hits):
        if candidate.pk in seen:
            continue
        seen.add(candidate.pk)
        merged.append(candidate)
        if len(merged) >= limit:
            break
    return merged
