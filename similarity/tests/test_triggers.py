"""The three creation hooks queue a check when enabled — and only then."""

from __future__ import annotations

import pytest
from django.contrib.auth.models import AnonymousUser
from django.urls import reverse

from advisories.models import Advisory
from advisories.services import submit_triage_report
from similarity.models import SimilarityCheck

pytestmark = pytest.mark.django_db

FORMSET_SECTIONS = ("aliases", "cwe_ids", "references", "severity", "credits", "affected")


def empty_formsets_payload() -> dict[str, str]:
    payload: dict[str, str] = {}
    for prefix in FORMSET_SECTIONS:
        payload[f"{prefix}-TOTAL_FORMS"] = "0"
        payload[f"{prefix}-INITIAL_FORMS"] = "0"
        payload[f"{prefix}-MIN_NUM_FORMS"] = "0"
        payload[f"{prefix}-MAX_NUM_FORMS"] = "1000"
    return payload


def _intake_request(rf):
    request = rf.post("/report/")
    request.user = AnonymousUser()
    return request


# ---- public intake ---------------------------------------------------------


def test_triage_submission_queues_check_when_enabled(enable_similarity, make_project, rf):
    advisory = submit_triage_report(
        request=_intake_request(rf),
        project=make_project("trigger-intake"),
        summary="Heap overflow in the parser",
        details="A crafted file overflows a fixed-size buffer.",
    )
    assert SimilarityCheck.objects.get(advisory=advisory).status == "queued"


def test_triage_submission_noop_when_disabled(make_project, rf):
    advisory = submit_triage_report(
        request=_intake_request(rf),
        project=make_project("trigger-intake-off"),
        summary="s",
        details="d",
    )
    assert not SimilarityCheck.objects.filter(advisory=advisory).exists()


@pytest.mark.django_db(transaction=True)
def test_broker_failure_never_breaks_intake(enable_similarity, make_project, rf, monkeypatch):
    # transaction=True so the on_commit enqueue actually fires; a broker
    # outage inside .delay must be swallowed (safe_enqueue), leaving the
    # check queued for the panel's re-run recovery path.
    def explode(*args, **kwargs):
        raise ConnectionError("broker down")

    monkeypatch.setattr("similarity.tasks.run_similarity_check.delay", explode)
    advisory = submit_triage_report(
        request=_intake_request(rf),
        project=make_project("trigger-broker"),
        summary="s",
        details="d",
    )
    assert SimilarityCheck.objects.get(advisory=advisory).status == "queued"


# ---- manual creation view ----------------------------------------------------


def test_advisory_create_view_queues_check(enable_similarity, make_user, make_project, client):
    project = make_project("trigger-create")
    member = make_user(email="creator@example.org", groups=[project.security_team.name])
    client.force_login(member)
    response = client.post(
        reverse("advisories:create"),
        data={
            "project": project.pk,
            "summary": "Use-after-free in the renderer",
            "details": "A crafted document frees the same object twice.",
            **empty_formsets_payload(),
        },
    )
    assert response.status_code == 302, response.content
    advisory = Advisory.objects.get(project=project)
    assert SimilarityCheck.objects.filter(advisory=advisory).exists()


def test_advisory_create_view_noop_when_disabled(make_user, make_project, client):
    project = make_project("trigger-create-off")
    member = make_user(email="creator2@example.org", groups=[project.security_team.name])
    client.force_login(member)
    response = client.post(
        reverse("advisories:create"),
        data={"project": project.pk, "summary": "s", "details": "d", **empty_formsets_payload()},
    )
    assert response.status_code == 302, response.content
    assert not SimilarityCheck.objects.exists()


# ---- GHSA import ---------------------------------------------------------------


def test_ghsa_creation_triggers_once(enable_similarity, make_project, monkeypatch):
    from ghsa import services as ghsa_services

    # The GitHub sync is network-bound; the hook fires regardless of its outcome.
    monkeypatch.setattr(ghsa_services, "sync_single_ghsa", lambda advisory, by: None)
    project = make_project("trigger-ghsa")
    advisory = ghsa_services.create_ghsa_linked_advisory(
        project=project, ghsa_id="GHSA-aaaa-bbbb-cccc", owner="eclipse", repo="widget", by=None
    )
    assert SimilarityCheck.objects.filter(advisory=advisory).count() == 1

    again = ghsa_services.create_ghsa_linked_advisory(
        project=project, ghsa_id="GHSA-aaaa-bbbb-cccc", owner="eclipse", repo="widget", by=None
    )
    assert again == advisory
    # The idempotent early return must not re-trigger a check.
    assert SimilarityCheck.objects.filter(advisory=advisory).count() == 1
