from __future__ import annotations

import pytest

from advisories.models import Advisory
from audit.models import Action, AuditLogEntry
from similarity import services
from similarity.models import AdvisoryFingerprint, SimilarityCheck

pytestmark = pytest.mark.django_db


@pytest.fixture
def project(make_project):
    return make_project("services-proj")


@pytest.fixture
def advisory(project):
    return Advisory.objects.create(
        project=project,
        summary="Reflected XSS in the search box",
        details="A crafted query parameter is echoed unescaped.",
        aliases=["CVE-2026-0001"],
    )


# ---- fingerprint cache ------------------------------------------------------


def test_ensure_fingerprint_skips_when_hash_fresh(advisory, fake_llm):
    payload = advisory.to_payload()
    first = services.ensure_fingerprint(advisory, payload, client=fake_llm)
    assert first is not None
    assert first.provider == "fake"
    assert fake_llm.call_kinds() == ["fingerprint"]

    again = services.ensure_fingerprint(advisory, payload, client=fake_llm)
    assert again.pk == first.pk
    assert fake_llm.call_kinds() == ["fingerprint"]  # no second LLM call


def test_ensure_fingerprint_regenerates_on_content_change(advisory, fake_llm):
    payload = advisory.to_payload()
    first = services.ensure_fingerprint(advisory, payload, client=fake_llm)
    changed = {**payload, "summary": "Stored XSS in the comment renderer"}
    second = services.ensure_fingerprint(advisory, changed, client=fake_llm)
    assert second.pk == first.pk  # updated in place (OneToOne)
    assert second.content_hash != first.content_hash
    assert fake_llm.call_kinds() == ["fingerprint", "fingerprint"]


def test_ensure_fingerprint_returns_none_for_empty_content(project, fake_llm):
    empty = Advisory.objects.create(project=project)
    assert services.ensure_fingerprint(empty, empty.to_payload(), client=fake_llm) is None
    assert fake_llm.calls == []
    assert not AdvisoryFingerprint.objects.filter(advisory=empty).exists()


# ---- request_check gating ----------------------------------------------------


def test_request_check_disabled_is_noop(advisory):
    assert services.request_check(advisory) is None
    assert not SimilarityCheck.objects.exists()
    assert not AuditLogEntry.objects.filter(action=Action.SIMILARITY_CHECK_STARTED).exists()


def test_request_check_creates_queued_row_and_audit(enable_similarity, advisory, make_user):
    user = make_user(email="requester@example.org")
    check = services.request_check(advisory, by=user)
    assert check is not None
    assert check.status == "queued"
    assert check.version.payload["summary"] == advisory.summary
    assert check.enqueued_by == user
    assert AuditLogEntry.objects.filter(
        action=Action.SIMILARITY_CHECK_STARTED, advisory=advisory
    ).exists()


def test_request_check_in_flight_guard(enable_similarity, advisory):
    services.request_check(advisory)
    with pytest.raises(services.SimilarityCheckInProgress):
        services.request_check(advisory)
    # The safe wrapper swallows the collision (and everything else).
    services.request_check_safe(advisory)
    assert SimilarityCheck.objects.filter(advisory=advisory).count() == 1


def test_request_check_safe_never_raises(enable_similarity, advisory, monkeypatch):
    monkeypatch.setattr(
        "similarity.services.request_check", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError)
    )
    services.request_check_safe(advisory)  # must not raise


# ---- mark_failed redaction ----------------------------------------------------


def test_mark_failed_redacts_and_caps(enable_similarity, advisory):
    check = services.request_check(advisory)
    services.mark_failed(check, error="boom token=supersecret123 " + "x" * 9000)
    check.refresh_from_db()
    assert "supersecret123" not in check.last_error
    assert "token=***" in check.last_error
    assert len(check.last_error) <= 8000


# ---- judge post-processing -----------------------------------------------------


def test_postprocess_drops_hallucinated_dedups_clamps_and_ranks():
    data = {
        "matches": [
            {"candidate_id": 999, "confidence": 90, "rationale": "hallucinated"},
            {"candidate_id": 1, "confidence": 40, "rationale": "first"},
            {"candidate_id": 1, "confidence": 70, "rationale": "dup keeps max"},
            {"candidate_id": 2, "confidence": 500, "rationale": "clamped high"},
            {"candidate_id": 3, "confidence": -5, "rationale": "clamped low, floored"},
            {"candidate_id": 4, "confidence": 19, "rationale": "below floor"},
            {"candidate_id": "5", "confidence": 80, "rationale": "non-int id dropped"},
            "not-a-dict",
        ]
    }
    out = services._postprocess_matches(data, valid_ids={1, 2, 3, 4, 5}, min_confidence=20)
    assert out == [(2, 100, "clamped high"), (1, 70, "dup keeps max")]


def test_postprocess_caps_at_five():
    data = {
        "matches": [
            {"candidate_id": i, "confidence": 30 + i, "rationale": f"c{i}"} for i in range(1, 9)
        ]
    }
    out = services._postprocess_matches(data, valid_ids=set(range(1, 9)), min_confidence=20)
    assert len(out) == services.MAX_MATCHES
    assert [pk for pk, _conf, _r in out] == [8, 7, 6, 5, 4]
