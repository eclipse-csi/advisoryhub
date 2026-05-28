"""publication.publish refreshes the linked GHSA before snapshotting."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.core.exceptions import PermissionDenied

from advisories.models import Advisory, Kind, State
from projects.models import ProjectGitHubRepository
from publication import services as pub


@pytest.mark.django_db
def test_publish_blocks_when_ghsa_is_draft(
    make_user, make_project, admin_group, ghsa_settings, ghsa_payload, settings
):
    admin = make_user(email="admin@example.org", groups=[settings.OIDC_ADMIN_GROUP])
    project = make_project("eclipse-x", is_mature_publisher=True)
    ProjectGitHubRepository.objects.create(
        project=project, owner="eclipse", name="x", last_seen_in_pmi_at="2026-05-14T12:00:00Z"
    )
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="x",
        state=State.DRAFT,
    )
    draft_payload = dict(ghsa_payload, state="draft")
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.get_advisory.return_value = draft_payload
        with pytest.raises(PermissionDenied):
            pub.publish(advisory, by=admin)


@pytest.mark.django_db
def test_publish_proceeds_when_ghsa_is_published(
    make_user, make_project, admin_group, ghsa_settings, ghsa_payload, settings
):
    admin = make_user(email="admin@example.org", groups=[settings.OIDC_ADMIN_GROUP])
    project = make_project("eclipse-x", is_mature_publisher=True)
    ProjectGitHubRepository.objects.create(
        project=project, owner="eclipse", name="x", last_seen_in_pmi_at="2026-05-14T12:00:00Z"
    )
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-abcd-1234-efgh",
        ghsa_owner="eclipse",
        ghsa_repo="x",
        state=State.DRAFT,
    )
    # publish() will enqueue run_publication; since the publication repo
    # is empty in tests, we expect the task to enter QUEUED (and then run
    # eagerly, but probably fail due to PUB_REPO_URL being empty). The
    # point of this test is just that the GHSA refresh + state check
    # didn't block.
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.get_advisory.return_value = ghsa_payload
        task = pub.publish(advisory, by=admin)
    assert task.pk is not None
    advisory.refresh_from_db()
    # Refresh populated GHSA fields:
    assert advisory.summary == "Path traversal in example library"
