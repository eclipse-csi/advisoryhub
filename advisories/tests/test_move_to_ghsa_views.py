"""View tests for the "Move to GHSA" action (INV-GHSA-4).

``config.settings.test`` force-disables step-up and rate limiting, so these
focus on the permission gate, the live-PVR picker, repo parsing, and the
redirect/flash contract. The heavy lifting (`move_advisory_to_ghsa`) is patched
out — it has its own service tests in ``ghsa/tests/test_move_to_ghsa.py``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.urls import reverse

from advisories.models import Advisory, Kind, State
from projects.models import ProjectGitHubRepository


@pytest.fixture
def project_a(make_project):
    return make_project("project-a")


@pytest.fixture
def member_a(make_user, project_a):
    return make_user(email="member-a@example.org", groups=[project_a.security_team.name])


@pytest.fixture
def outsider(make_user):
    return make_user(email="outsider@example.org")


@pytest.fixture
def pvr_repo(project_a):
    return ProjectGitHubRepository.objects.create(
        project=project_a,
        owner="eclipse",
        name="example",
        last_seen_in_pmi_at="2026-05-14T12:00:00Z",
        pvr_enabled=True,
        pvr_checked_at="2026-05-14T12:00:00Z",
    )


@pytest.fixture
def native_advisory(project_a):
    return Advisory.objects.create(
        project=project_a, state=State.TRIAGE, kind=Kind.NATIVE, summary="misfiled"
    )


@pytest.mark.django_db
def test_modal_lists_pvr_repos_for_owner(client, member_a, native_advisory, pvr_repo, settings):
    settings.GHSA_FEATURE_ENABLED = True
    client.force_login(member_a)
    with patch("ghsa.services.refresh_pvr_status") as refresh:
        resp = client.get(
            reverse("advisories:move_to_ghsa_modal", args=[native_advisory.advisory_id])
        )
    assert resp.status_code == 200
    refresh.assert_called_once()
    assert b"eclipse/example" in resp.content


@pytest.mark.django_db
def test_modal_forbidden_for_outsider(client, outsider, native_advisory, pvr_repo, settings):
    settings.GHSA_FEATURE_ENABLED = True
    client.force_login(outsider)
    resp = client.get(reverse("advisories:move_to_ghsa_modal", args=[native_advisory.advisory_id]))
    assert resp.status_code == 404


@pytest.mark.django_db
def test_post_moves_and_redirects(client, member_a, native_advisory, pvr_repo, settings):
    settings.GHSA_FEATURE_ENABLED = True
    client.force_login(member_a)
    with patch("ghsa.services.move_advisory_to_ghsa", return_value=native_advisory) as move:
        resp = client.post(
            reverse("advisories:move_to_ghsa", args=[native_advisory.advisory_id]),
            {"repo": "eclipse/example"},
        )
    assert resp.status_code == 302
    assert resp.url == reverse("advisories:detail", args=[native_advisory.advisory_id])
    move.assert_called_once()
    _, kwargs = move.call_args
    assert kwargs["owner"] == "eclipse"
    assert kwargs["repo"] == "example"
    assert kwargs["by"] == member_a


@pytest.mark.django_db
def test_post_forbidden_for_outsider(client, outsider, native_advisory, pvr_repo, settings):
    settings.GHSA_FEATURE_ENABLED = True
    client.force_login(outsider)
    with patch("ghsa.services.move_advisory_to_ghsa") as move:
        resp = client.post(
            reverse("advisories:move_to_ghsa", args=[native_advisory.advisory_id]),
            {"repo": "eclipse/example"},
        )
    assert resp.status_code == 403
    move.assert_not_called()


@pytest.mark.django_db
def test_post_without_repo_is_rejected(client, member_a, native_advisory, pvr_repo, settings):
    settings.GHSA_FEATURE_ENABLED = True
    client.force_login(member_a)
    with patch("ghsa.services.move_advisory_to_ghsa") as move:
        resp = client.post(
            reverse("advisories:move_to_ghsa", args=[native_advisory.advisory_id]),
            {"repo": ""},
        )
    assert resp.status_code == 302  # back to detail with an error flash
    move.assert_not_called()
