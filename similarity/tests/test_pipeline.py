"""End-to-end pipeline tests with the LLM client stubbed.

The Celery task is invoked directly (``run_similarity_check(check.pk)``) —
under plain ``django_db`` the ``transaction.on_commit`` enqueue never fires,
which keeps creation and execution independently controllable.
"""

from __future__ import annotations

import pytest

from advisories.models import Advisory
from audit.models import Action, AuditLogEntry
from similarity import services
from similarity.llm import LlmError
from similarity.models import AdvisoryFingerprint, SimilarityCandidate
from similarity.tasks import run_similarity_check

pytestmark = pytest.mark.django_db


@pytest.fixture
def project(make_project):
    return make_project("pipeline-proj")


@pytest.fixture
def target(project):
    return Advisory.objects.create(
        project=project,
        summary="Path traversal in the archive extractor",
        details="Crafted zip entries escape the extraction root.",
        aliases=["CVE-2026-4242"],
    )


@pytest.fixture
def candidate(project):
    return Advisory.objects.create(
        project=project,
        summary="Zip-slip path traversal during archive extraction",
        details="Entries containing ../ escape the target directory.",
        aliases=["CVE-2026-4242"],
    )


def _queued_check(advisory):
    return services.request_check(advisory)


def test_happy_path_persists_matches_fingerprint_and_audit(
    enable_similarity, fake_llm, target, candidate
):
    fake_llm.judge_matches = [
        {"candidate_id": candidate.pk, "confidence": 87, "rationale": "Same CVE alias."}
    ]
    check = _queued_check(target)
    assert run_similarity_check(check.pk) == "succeeded"

    check.refresh_from_db()
    assert check.status == "succeeded"
    assert check.provider == "fake"
    assert check.candidate_pool_size == 1
    rows = list(check.candidates.all())
    assert len(rows) == 1
    assert rows[0].matched_advisory == candidate
    assert rows[0].confidence == 87
    assert rows[0].rank == 1
    assert AdvisoryFingerprint.objects.filter(advisory=target).exists()
    assert fake_llm.call_kinds() == ["fingerprint", "judge"]
    assert AuditLogEntry.objects.filter(
        action=Action.SIMILARITY_CHECK_COMPLETED, advisory=target
    ).exists()


def test_fresh_fingerprint_skips_first_llm_call(enable_similarity, fake_llm, target, candidate):
    services.ensure_fingerprint(target, target.to_payload(), client=fake_llm)
    assert fake_llm.call_kinds() == ["fingerprint"]
    check = _queued_check(target)
    run_similarity_check(check.pk)
    assert fake_llm.call_kinds() == ["fingerprint", "judge"]  # judge only on this run


def test_judge_uses_candidate_fingerprint_when_fresh(
    enable_similarity, fake_llm, target, candidate
):
    services.ensure_fingerprint(candidate, candidate.to_payload(), client=fake_llm)
    check = _queued_check(target)
    run_similarity_check(check.pk)
    judge_call = next(call for call in fake_llm.calls if call["kind"] == "judge")
    assert f"[id={candidate.pk}]" in judge_call["user"]
    assert "fingerprint: class: XSS" in judge_call["user"]  # canned fingerprint text


def test_llm_failure_marks_failed_with_redacted_error(
    enable_similarity, fake_llm, target, candidate
):
    fake_llm.judge_error = LlmError("HTTP 500: boom token=topsecret999")
    check = _queued_check(target)
    assert run_similarity_check(check.pk) == "failed"
    check.refresh_from_db()
    assert check.status == "failed"
    assert "topsecret999" not in check.last_error
    assert "llm:" in check.last_error
    assert AuditLogEntry.objects.filter(
        action=Action.SIMILARITY_CHECK_FAILED, advisory=target
    ).exists()
    assert not SimilarityCandidate.objects.filter(check_run=check).exists()


def test_task_is_idempotent_on_terminal_status(enable_similarity, fake_llm, target, candidate):
    check = _queued_check(target)
    run_similarity_check(check.pk)
    calls_after_first = len(fake_llm.calls)
    assert run_similarity_check(check.pk) == "succeeded"  # early return, no new calls
    assert len(fake_llm.calls) == calls_after_first


def test_failed_check_can_be_rerun_by_redelivery(enable_similarity, fake_llm, target, candidate):
    fake_llm.judge_error = LlmError("transient")
    check = _queued_check(target)
    run_similarity_check(check.pk)
    fake_llm.judge_error = None
    assert run_similarity_check(check.pk) == "succeeded"
    check.refresh_from_db()
    assert check.attempts == 2
    assert check.last_error == ""


def test_empty_content_short_circuits_without_llm(enable_similarity, fake_llm, project):
    empty = Advisory.objects.create(project=project)
    check = _queued_check(empty)
    assert run_similarity_check(check.pk) == "succeeded"
    check.refresh_from_db()
    assert check.note == services.NOTE_NO_CONTENT
    assert fake_llm.calls == []
    assert not AdvisoryFingerprint.objects.filter(advisory=empty).exists()


def test_lone_advisory_skips_judge_but_persists_fingerprint(enable_similarity, fake_llm, target):
    check = _queued_check(target)
    assert run_similarity_check(check.pk) == "succeeded"
    check.refresh_from_db()
    assert check.note == services.NOTE_NO_CANDIDATES
    assert fake_llm.call_kinds() == ["fingerprint"]
    assert AdvisoryFingerprint.objects.filter(advisory=target).exists()


def test_missing_check_row_returns_missing():
    assert run_similarity_check(99_999_999) == "missing"
