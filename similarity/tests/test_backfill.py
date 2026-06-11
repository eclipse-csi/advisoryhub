from __future__ import annotations

from io import StringIO

import pytest
from django.core.management import CommandError, call_command

from advisories.models import Advisory
from similarity.models import AdvisoryFingerprint

pytestmark = pytest.mark.django_db


def _run(*args) -> str:
    out = StringIO()
    call_command("backfill_fingerprints", *args, stdout=out)
    return out.getvalue()


def test_refuses_when_disabled():
    with pytest.raises(CommandError, match="SIMILARITY_CHECK_ENABLED"):
        call_command("backfill_fingerprints")


def test_generates_skips_fresh_and_dry_runs(enable_similarity, fake_llm, make_project):
    project = make_project("backfill-proj")
    Advisory.objects.create(project=project, summary="Flaw number one")
    Advisory.objects.create(project=project, summary="Flaw number two")
    Advisory.objects.create(project=project)  # no content → skipped

    out = _run("--dry-run")
    assert "would generate 2" in out
    assert "empty 1" in out
    assert AdvisoryFingerprint.objects.count() == 0
    assert fake_llm.calls == []

    out = _run()
    assert "generated 2" in out
    assert AdvisoryFingerprint.objects.count() == 2
    assert fake_llm.call_kinds() == ["fingerprint", "fingerprint"]

    out = _run()  # second pass: everything fresh, no further LLM calls
    assert "generated 0" in out
    assert "fresh 2" in out
    assert len(fake_llm.calls) == 2


def test_limit_and_project_scope(enable_similarity, fake_llm, make_project):
    project = make_project("backfill-limit")
    other = make_project("backfill-other")
    Advisory.objects.create(project=project, summary="One")
    Advisory.objects.create(project=project, summary="Two")
    Advisory.objects.create(project=other, summary="Three")

    _run("--limit", "1")
    assert AdvisoryFingerprint.objects.count() == 1

    AdvisoryFingerprint.objects.all().delete()
    fake_llm.calls.clear()
    _run("--project", other.slug)
    assert AdvisoryFingerprint.objects.count() == 1
    assert AdvisoryFingerprint.objects.filter(advisory__project=other).count() == 1
