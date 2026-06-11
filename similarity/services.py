"""Duplicate-detection orchestration.

Entry points:

* :func:`request_check` — creates a ``SimilarityCheck`` pinned to the latest
  :class:`AdvisoryVersion` and enqueues ``run_similarity_check``. This is the
  single egress gate: it returns ``None`` while ``SIMILARITY_CHECK_ENABLED``
  is off, so no caller can ship advisory content to the LLM provider while
  the feature is disabled (INV-SIM-2).
* :func:`request_check_safe` — wrapper for the advisory-creation hooks: a
  failed enqueue must never fail the intake/create/GHSA-sync operation that
  triggered it.
* :func:`run_check_sync` — the pipeline body executed by the Celery task
  (``similarity.tasks.run_similarity_check``); directly callable in tests.

Mirrors ``publication.services`` throughout: row lock + in-flight guard,
``transaction.on_commit`` + ``safe_enqueue``, redacted ``mark_failed``.
"""

from __future__ import annotations

import hashlib
import json
import logging

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from advisories import services as advisory_services
from advisories.models import Advisory
from audit.models import Action
from audit.services import record
from common import metrics
from common.enqueue import safe_enqueue
from common.users import actor_or_none

from . import llm, prefilter
from .llm import prompts
from .models import (
    AdvisoryFingerprint,
    SimilarityCandidate,
    SimilarityCheck,
    SimilarityCheckStatus,
)

log = logging.getLogger(__name__)

MAX_MATCHES = 5

# The payload subset that makes two reports "the same flaw" — the fingerprint
# content hash covers exactly these keys, so cosmetic edits (references,
# credits) don't invalidate the cached fingerprint.
_HASH_FIELDS = (
    "summary",
    "details",
    "aliases",
    "assigned_cve_id",
    "affected",
    "severity",
    "cwe_ids",
    "ghsa_id",
)

NOTE_NO_CONTENT = "No content to compare yet."
NOTE_NO_CANDIDATES = "No other advisories in this project to compare against."


class SimilarityCheckInProgress(Exception):
    """Raised when a check request collides with an in-flight run."""


def fingerprint_source(payload: dict) -> dict:
    return {key: payload.get(key) for key in _HASH_FIELDS}


def payload_content_hash(payload: dict) -> str:
    canonical = json.dumps(
        fingerprint_source(payload),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def has_meaningful_content(payload: dict) -> bool:
    summary = (payload.get("summary") or "").strip()
    details = (payload.get("details") or "").strip()
    return bool(summary or details)


def _live_hash_subset(advisory: Advisory) -> dict:
    """The hash subset built from live fields — equivalent to the advisory's
    latest payload for these keys (``to_payload`` copies them verbatim)."""
    return {key: getattr(advisory, key) for key in _HASH_FIELDS}


@transaction.atomic
def request_check(advisory: Advisory, *, by=None) -> SimilarityCheck | None:
    """Queue a duplicate check for ``advisory``; returns ``None`` when disabled.

    Raises :class:`SimilarityCheckInProgress` if a queued/running check
    already exists for the same advisory.
    """
    if not settings.SIMILARITY_CHECK_ENABLED:
        return None
    # Serialize concurrent requesters for this advisory (mirror publication).
    locked = Advisory.objects.select_for_update().filter(pk=advisory.pk).first()
    if locked is None:
        return None
    in_flight = SimilarityCheck.objects.filter(
        advisory=advisory,
        status__in=[SimilarityCheckStatus.QUEUED, SimilarityCheckStatus.RUNNING],
    ).exists()
    if in_flight:
        raise SimilarityCheckInProgress(
            f"A duplicate check for {advisory.advisory_id} is already in progress."
        )
    version = advisory_services.latest_version(advisory)
    if version is None:
        # Every advisory has v1 from the post_save signal; a missing version
        # means a code path bypassed it — skip rather than judge nothing.
        log.warning("similarity: advisory %s has no version; check skipped", advisory.pk)
        return None
    check = SimilarityCheck.objects.create(
        advisory=advisory, version=version, enqueued_by=actor_or_none(by)
    )
    record(
        action=Action.SIMILARITY_CHECK_STARTED,
        actor=by,
        advisory=advisory,
        new_value={"check_id": check.pk, "version_id": version.pk, "version": version.version},
    )
    transaction.on_commit(lambda: _enqueue(check.pk))
    return check


def request_check_safe(advisory: Advisory, *, by=None) -> None:
    """Creation-hook wrapper: never raises, never fails the parent operation."""
    try:
        request_check(advisory, by=by)
    except SimilarityCheckInProgress:
        pass
    except Exception:
        log.warning("similarity: check enqueue failed for advisory %s", advisory.pk, exc_info=True)


def _enqueue(check_pk: int) -> None:
    # Broker offline: safe_enqueue leaves the check 'queued'; the panel's
    # re-run button is the recovery path once the broker is back.
    from .tasks import run_similarity_check

    safe_enqueue(run_similarity_check, check_pk)


def mark_running(check: SimilarityCheck) -> SimilarityCheck:
    check.status = SimilarityCheckStatus.RUNNING
    check.attempts += 1
    check.started_at = timezone.now()
    check.save(update_fields=["status", "attempts", "started_at"])
    metrics.similarity_check_total.labels(status="started").inc()
    return check


def mark_succeeded(check: SimilarityCheck, *, note: str = "") -> SimilarityCheck:
    check.status = SimilarityCheckStatus.SUCCEEDED
    check.note = note
    check.finished_at = timezone.now()
    check.last_error = ""
    check.save(update_fields=["status", "note", "finished_at", "last_error"])
    metrics.similarity_check_total.labels(status="succeeded").inc()
    return check


def mark_failed(check: SimilarityCheck, *, error: str) -> SimilarityCheck:
    from audit.services import redact_secrets

    check.status = SimilarityCheckStatus.FAILED
    check.finished_at = timezone.now()
    check.last_error = redact_secrets(error or "")[:8000]
    check.save(update_fields=["status", "finished_at", "last_error"])
    metrics.similarity_check_total.labels(status="failed").inc()
    return check


def ensure_fingerprint(
    advisory: Advisory, payload: dict, *, client=None
) -> AdvisoryFingerprint | None:
    """Return a fresh fingerprint for ``advisory``, generating it if needed.

    Skips the LLM call when the persisted fingerprint's content hash still
    matches ``payload``. Returns ``None`` when the payload has no meaningful
    content to digest.
    """
    if not has_meaningful_content(payload):
        return None
    content_hash = payload_content_hash(payload)
    existing = AdvisoryFingerprint.objects.filter(advisory=advisory).first()
    if existing is not None and existing.content_hash == content_hash:
        return existing
    client = client or llm.get_client()
    data = client.complete_json(
        system=prompts.FINGERPRINT_SYSTEM,
        user=prompts.fingerprint_user(payload),
        schema=prompts.FINGERPRINT_SCHEMA,
        max_tokens=prompts.FINGERPRINT_MAX_TOKENS,
    )
    fingerprint, _created = AdvisoryFingerprint.objects.update_or_create(
        advisory=advisory,
        defaults={
            "content_hash": content_hash,
            "text": prompts.render_fingerprint(data),
            "provider": client.provider,
            "model": client.model,
        },
    )
    return fingerprint


def run_check_sync(check: SimilarityCheck) -> str:
    """The check pipeline: prefilter → fingerprint → judge → persist top 5.

    All advisory content comes from the pinned ``check.version.payload``
    (INV-SIM-4). At most two LLM calls; zero when the payload is empty.
    """
    payload = check.version.payload
    advisory = check.advisory

    if not has_meaningful_content(payload):
        mark_succeeded(check, note=NOTE_NO_CONTENT)
        _record_completed(check, matches=0)
        return SimilarityCheckStatus.SUCCEEDED

    candidates = prefilter.candidate_advisories(
        advisory, payload, limit=settings.SIMILARITY_CANDIDATE_LIMIT
    )
    client = llm.get_client()
    check.candidate_pool_size = len(candidates)
    check.provider = client.provider
    check.model = client.model
    check.save(update_fields=["candidate_pool_size", "provider", "model"])

    # LLM call #1 (skipped when the cached fingerprint is fresh). Persisted
    # even when there are no candidates yet — it becomes judge input for
    # future checks of other advisories in this project.
    fingerprint = ensure_fingerprint(advisory, payload, client=client)

    if not candidates:
        mark_succeeded(check, note=NOTE_NO_CANDIDATES)
        _record_completed(check, matches=0)
        return SimilarityCheckStatus.SUCCEEDED

    by_pk = {candidate.pk: candidate for candidate in candidates}
    fingerprints = _candidate_fingerprints(candidates)
    blocks = [
        _candidate_block(candidate, fingerprints.get(candidate.pk)) for candidate in candidates
    ]
    data = client.complete_json(  # LLM call #2
        system=prompts.JUDGE_SYSTEM,
        user=prompts.judge_user(
            advisory_id=advisory.advisory_id,
            payload=payload,
            fingerprint=fingerprint.text if fingerprint else "",
            candidates="\n\n".join(blocks),
        ),
        schema=prompts.JUDGE_SCHEMA,
        max_tokens=prompts.JUDGE_MAX_TOKENS,
    )

    matches = _postprocess_matches(
        data, valid_ids=set(by_pk), min_confidence=settings.SIMILARITY_MIN_CONFIDENCE
    )
    SimilarityCandidate.objects.bulk_create(
        SimilarityCandidate(
            check_run=check,
            matched_advisory=by_pk[pk],
            confidence=confidence,
            rationale=rationale[:500],
            rank=index + 1,
        )
        for index, (pk, confidence, rationale) in enumerate(matches)
    )
    mark_succeeded(check)
    _record_completed(check, matches=len(matches))
    return SimilarityCheckStatus.SUCCEEDED


def _candidate_fingerprints(candidates: list[Advisory]) -> dict[int, AdvisoryFingerprint]:
    return {
        fp.advisory_id: fp for fp in AdvisoryFingerprint.objects.filter(advisory__in=candidates)
    }


def _candidate_block(candidate: Advisory, fingerprint: AdvisoryFingerprint | None) -> str:
    """Judge-prompt block: the cached fingerprint when fresh, else a raw excerpt.

    Stale/missing candidate fingerprints are never regenerated inline — that
    would be an unbounded number of LLM calls; the backfill command and each
    advisory's own checks keep the corpus warm.
    """
    fingerprint_text = None
    if fingerprint is not None:
        live_subset = _live_hash_subset(candidate)
        if fingerprint.content_hash == payload_content_hash(live_subset):
            fingerprint_text = fingerprint.text
    return prompts.candidate_block(
        pk=candidate.pk,
        advisory_id=candidate.advisory_id,
        state=candidate.state,
        fingerprint=fingerprint_text,
        summary=candidate.summary,
        details=candidate.details,
        identifiers=prompts.payload_identifiers(_live_hash_subset(candidate)),
    )


def _postprocess_matches(
    data: dict, *, valid_ids: set[int], min_confidence: int
) -> list[tuple[int, int, str]]:
    """Normalize the judge reply: drop hallucinated ids, dedup keeping the max
    confidence, clamp to 0–100, apply the floor, keep the top ``MAX_MATCHES``."""
    best: dict[int, tuple[int, str]] = {}
    for item in data.get("matches") or []:
        if not isinstance(item, dict):
            continue
        pk = item.get("candidate_id")
        if not isinstance(pk, int) or pk not in valid_ids:
            continue
        raw_confidence = item.get("confidence")
        if not isinstance(raw_confidence, int | float | str):
            continue
        try:
            confidence = int(raw_confidence)
        except ValueError:
            continue
        confidence = max(0, min(100, confidence))
        rationale = str(item.get("rationale") or "")
        if pk not in best or confidence > best[pk][0]:
            best[pk] = (confidence, rationale)
    ranked = sorted(best.items(), key=lambda kv: kv[1][0], reverse=True)
    return [
        (pk, confidence, rationale)
        for pk, (confidence, rationale) in ranked
        if confidence >= min_confidence
    ][:MAX_MATCHES]


def _record_completed(check: SimilarityCheck, *, matches: int) -> None:
    record(
        action=Action.SIMILARITY_CHECK_COMPLETED,
        advisory=check.advisory,
        new_value={
            "check_id": check.pk,
            "matches": matches,
            "candidate_pool": check.candidate_pool_size,
        },
    )
