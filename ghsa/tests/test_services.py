"""Services-layer tests for the GHSA integration.

These exercise the parts that take an Advisory and reconcile it with a
GHSA payload: discovery (auto-create), refresh (update existing), CVE
conflict detection, and the publish-time refresh that gates the
publication pipeline.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.core.exceptions import PermissionDenied

from advisories.models import Advisory, GhsaCvePushStatus, GhsaState, Kind, State
from ghsa import services
from ghsa.models import GhsaCvePushTaskStatus
from projects.models import ProjectGitHubRepository


@pytest.fixture
def project_with_repo(make_project, db):
    project = make_project("eclipse-example")
    ProjectGitHubRepository.objects.create(
        project=project,
        owner="eclipse",
        name="example",
        last_seen_in_pmi_at="2026-05-14T12:00:00Z",
    )
    return project


@pytest.mark.django_db
def test_create_ghsa_linked_advisory_is_idempotent(project_with_repo, ghsa_payload, ghsa_settings):
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.get_advisory.return_value = ghsa_payload
        a1 = services.create_ghsa_linked_advisory(
            project=project_with_repo,
            ghsa_id="GHSA-abcd-1234-efgh",
            owner="eclipse",
            repo="example",
            by=None,
        )
        a2 = services.create_ghsa_linked_advisory(
            project=project_with_repo,
            ghsa_id="GHSA-abcd-1234-efgh",
            owner="eclipse",
            repo="example",
            by=None,
        )
    assert a1.pk == a2.pk
    a1.refresh_from_db()
    assert a1.kind == Kind.GHSA_LINKED
    assert a1.summary == "Path traversal in example library"


@pytest.mark.django_db
def test_sync_single_ghsa_marks_republish_required_for_published(
    project_with_repo, ghsa_payload, ghsa_settings
):
    advisory = Advisory.objects.create(
        project=project_with_repo,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
        state=State.PUBLISHED,
        published_at="2026-01-01T00:00:00Z",
    )
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.get_advisory.return_value = ghsa_payload
        services.sync_single_ghsa(advisory, by=None)
    advisory.refresh_from_db()
    assert advisory.republish_required is True
    assert advisory.ghsa_state == GhsaState.PUBLISHED


@pytest.mark.django_db
def test_sync_single_ghsa_detects_cve_conflict(project_with_repo, ghsa_payload, ghsa_settings):
    advisory = Advisory.objects.create(
        project=project_with_repo,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
        assigned_cve_id="CVE-2026-0001",
    )
    upstream = dict(ghsa_payload, cve_id="CVE-9999-9999")
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.get_advisory.return_value = upstream
        result = services.sync_single_ghsa(advisory, by=None)
    advisory.refresh_from_db()
    assert result["conflict"] is True
    # Internal CVE remains authoritative.
    assert advisory.assigned_cve_id == "CVE-2026-0001"
    assert advisory.ghsa_cve_conflict_detected_at is not None
    assert advisory.ghsa_cve_conflict_ghsa_value == "CVE-9999-9999"


@pytest.mark.django_db
def test_sync_single_ghsa_handles_upstream_deletion(project_with_repo, ghsa_settings):
    advisory = Advisory.objects.create(
        project=project_with_repo,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-deleted-aaaa-bbbb",
        ghsa_owner="eclipse",
        ghsa_repo="example",
        ghsa_state=GhsaState.PUBLISHED,
    )
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.get_advisory.return_value = None
        result = services.sync_single_ghsa(advisory, by=None)
    advisory.refresh_from_db()
    assert result["missing_upstream"] is True
    assert advisory.ghsa_state == GhsaState.CLOSED


@pytest.mark.django_db
def test_refresh_for_publish_blocks_draft_ghsa(project_with_repo, ghsa_payload, ghsa_settings):
    draft_payload = dict(ghsa_payload, state="draft")
    advisory = Advisory.objects.create(
        project=project_with_repo,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
    )
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.get_advisory.return_value = draft_payload
        with pytest.raises(PermissionDenied):
            services.refresh_for_publish(advisory, by=None)


@pytest.mark.django_db
def test_refresh_for_publish_blocks_when_cve_conflict(
    project_with_repo, ghsa_payload, ghsa_settings
):
    advisory = Advisory.objects.create(
        project=project_with_repo,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
        assigned_cve_id="CVE-2026-0001",
    )
    conflict_payload = dict(ghsa_payload, cve_id="CVE-9999-9999", state="published")
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.get_advisory.return_value = conflict_payload
        with pytest.raises(PermissionDenied):
            services.refresh_for_publish(advisory, by=None)


@pytest.mark.django_db
def test_refresh_for_publish_passes_through_for_native(make_project):
    project = make_project("native")
    advisory = Advisory.objects.create(project=project, kind=Kind.NATIVE)
    # Should not raise and should not call the client at all.
    services.refresh_for_publish(advisory, by=None)


@pytest.mark.django_db
def test_push_reserved_cve_marks_success(project_with_repo, ghsa_settings):
    advisory = Advisory.objects.create(
        project=project_with_repo,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
        assigned_cve_id="CVE-2026-0001",
    )
    push_task = services.enqueue_cve_push(advisory, "CVE-2026-0001", by=None)
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.update_advisory_cve.return_value = {"cve_id": "CVE-2026-0001"}
        services.push_reserved_cve_to_ghsa(push_task)
    push_task.refresh_from_db()
    advisory.refresh_from_db()
    assert push_task.status == GhsaCvePushTaskStatus.SUCCEEDED
    assert advisory.ghsa_cve_push_status == GhsaCvePushStatus.SUCCEEDED


@pytest.mark.django_db
def test_push_reserved_cve_records_failure_without_rollback(project_with_repo, ghsa_settings):
    from ghsa.client import GitHubApiError

    advisory = Advisory.objects.create(
        project=project_with_repo,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="example",
        assigned_cve_id="CVE-2026-0001",
    )
    push_task = services.enqueue_cve_push(advisory, "CVE-2026-0001", by=None)
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.update_advisory_cve.side_effect = GitHubApiError(
            "403 forbidden ghs_secret_token_value_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        )
        services.push_reserved_cve_to_ghsa(push_task)
    push_task.refresh_from_db()
    advisory.refresh_from_db()
    assert push_task.status == GhsaCvePushTaskStatus.FAILED
    assert advisory.ghsa_cve_push_status == GhsaCvePushStatus.FAILED
    # Internal CVE id is unchanged.
    assert advisory.assigned_cve_id == "CVE-2026-0001"
    # And the token from the error is redacted before it lands in the row.
    assert "ghs_secret_token" not in push_task.last_error


@pytest.mark.django_db
def test_sync_project_repos_soft_removes_dropped(make_project, ghsa_settings):
    project = make_project("eclipse-x")
    # Pre-populate two repos; PMI will only return one of them.
    from django.utils import timezone

    now = timezone.now()
    ProjectGitHubRepository.objects.create(
        project=project, owner="eclipse", name="x-keep", last_seen_in_pmi_at=now
    )
    ProjectGitHubRepository.objects.create(
        project=project, owner="eclipse", name="x-drop", last_seen_in_pmi_at=now
    )
    with patch("ghsa.services.fetch_project_repos") as mock_pmi:
        mock_pmi.return_value = [("eclipse", "x-keep")]
        services.sync_project_repos_from_pmi(project, by=None)
    keep = ProjectGitHubRepository.objects.get(project=project, name="x-keep")
    drop = ProjectGitHubRepository.objects.get(project=project, name="x-drop")
    assert keep.soft_removed_at is None
    assert drop.soft_removed_at is not None
