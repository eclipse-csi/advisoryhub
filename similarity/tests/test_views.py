from __future__ import annotations

import pytest
from django.urls import reverse

from access.models import Permission
from access.services import grant_to_user
from advisories.models import Advisory
from similarity import services
from similarity.models import SimilarityCandidate, SimilarityCheck

pytestmark = pytest.mark.django_db


@pytest.fixture
def world(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="member@example.org")
    project = make_project("views-proj", team_members=[member])
    advisory = Advisory.objects.create(
        project=project, summary="XSS in the editor", details="Crafted input executes."
    )
    other = Advisory.objects.create(
        project=project, summary="XSS in the editor toolbar", details="A similar flaw."
    )
    collaborator = make_user(email="collab@example.org")
    viewer = make_user(email="viewer@example.org")
    grant_to_user(advisory, collaborator, Permission.COLLABORATOR, by=member)
    grant_to_user(advisory, viewer, Permission.VIEWER, by=member)
    outsider = make_user(email="outsider@example.org")
    return {
        "admin": admin,
        "member": member,
        "collaborator": collaborator,
        "viewer": viewer,
        "outsider": outsider,
        "project": project,
        "advisory": advisory,
        "other": other,
    }


def _panel_url(world) -> str:
    return reverse("similarity:panel", args=[world["advisory"].advisory_id])


def _run_url(world) -> str:
    return reverse("similarity:run", args=[world["advisory"].advisory_id])


# ---- authorization (INV-SIM-1) ------------------------------------------------


def test_panel_permission_matrix(enable_similarity, world, client):
    expectations = [
        ("member", 200),
        ("admin", 200),
        ("collaborator", 403),
        ("viewer", 403),
        ("outsider", 403),
    ]
    for who, status in expectations:
        client.force_login(world[who])
        response = client.get(_panel_url(world), HTTP_HX_REQUEST="true")
        assert response.status_code == status, who
    client.logout()
    assert client.get(_panel_url(world)).status_code == 302  # login redirect


def test_run_permission_matrix(enable_similarity, world, client):
    client.force_login(world["collaborator"])
    assert client.post(_run_url(world)).status_code == 403
    client.force_login(world["viewer"])
    assert client.post(_run_url(world)).status_code == 403
    assert not SimilarityCheck.objects.exists()
    client.force_login(world["member"])
    assert client.post(_run_url(world)).status_code == 200
    assert SimilarityCheck.objects.filter(advisory=world["advisory"]).count() == 1


def test_endpoints_404_when_feature_disabled(world, client, settings):
    assert settings.SIMILARITY_CHECK_ENABLED is False
    client.force_login(world["member"])
    assert client.get(_panel_url(world)).status_code == 404
    assert client.post(_run_url(world)).status_code == 404


# ---- fragment states -----------------------------------------------------------


def test_panel_states_never_ran_pending_succeeded_failed(enable_similarity, world, client):
    client.force_login(world["member"])

    body = client.get(_panel_url(world), HTTP_HX_REQUEST="true").content.decode()
    assert "Never run" in body
    assert "Check for duplicates" in body
    assert "every 3s" not in body

    check = services.request_check(world["advisory"], by=world["member"])
    body = client.get(_panel_url(world), HTTP_HX_REQUEST="true").content.decode()
    assert 'hx-trigger="every 3s"' in body
    assert "Checking for similar advisories" in body
    assert "Re-run check" not in body  # no re-run while pending

    services.mark_succeeded(check)
    SimilarityCandidate.objects.create(
        check_run=check,
        matched_advisory=world["other"],
        confidence=87,
        rationale="Same flaw in the same component.",
        rank=1,
    )
    body = client.get(_panel_url(world), HTTP_HX_REQUEST="true").content.decode()
    assert "every 3s" not in body  # polling stops with the completed fragment
    assert world["other"].advisory_id in body
    assert "87%" in body
    assert "Same flaw in the same component." in body
    assert "Re-run check" in body

    services.mark_failed(check, error="llm: HTTP 500")
    body = client.get(_panel_url(world), HTTP_HX_REQUEST="true").content.decode()
    assert "Last error" in body
    assert "Re-run check" in body


def test_run_rerenders_pending_and_dedups_in_flight(enable_similarity, world, client):
    client.force_login(world["member"])
    body = client.post(_run_url(world)).content.decode()
    assert 'hx-trigger="every 3s"' in body
    # A second click while the first check is still queued must not stack runs.
    client.post(_run_url(world))
    assert SimilarityCheck.objects.filter(advisory=world["advisory"]).count() == 1


# ---- detail-page loader gating ---------------------------------------------------


def test_detail_page_loads_panel_for_owner_only(enable_similarity, world, client):
    detail = reverse("advisories:detail", args=[world["advisory"].advisory_id])
    client.force_login(world["member"])
    assert _panel_url(world) in client.get(detail).content.decode()
    client.force_login(world["collaborator"])
    assert _panel_url(world) not in client.get(detail).content.decode()


def test_detail_page_omits_panel_when_disabled(world, client):
    detail = reverse("advisories:detail", args=[world["advisory"].advisory_id])
    client.force_login(world["member"])
    assert _panel_url(world) not in client.get(detail).content.decode()
