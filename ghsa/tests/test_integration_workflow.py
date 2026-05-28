"""End-to-end-ish: CVE reservation on a GHSA-linked advisory pushes to GitHub."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from advisories.models import Advisory, GhsaCvePushStatus, Kind
from ghsa.models import GhsaCvePushTask, GhsaCvePushTaskStatus
from projects.models import ProjectGitHubRepository
from workflows import services as wf
from workflows.models import CveRequestStatus


@pytest.mark.django_db
def test_cve_reservation_for_ghsa_linked_enqueues_push(
    make_user, make_project, admin_group, ghsa_settings, settings
):
    admin = make_user(email="admin@example.org", groups=[settings.OIDC_ADMIN_GROUP])
    member = make_user(email="member@example.org")
    project = make_project("eclipse-x", team_members=[member])
    ProjectGitHubRepository.objects.create(
        project=project, owner="eclipse", name="x", last_seen_in_pmi_at="2026-05-14T12:00:00Z"
    )
    advisory = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        ghsa_owner="eclipse",
        ghsa_repo="x",
        created_by=member,
    )
    # Member opens a CVE request.
    task = wf.request_cve(advisory, by=member)
    assert task.status == CveRequestStatus.QUEUED

    # Admin reserves a CVE id. CELERY_TASK_ALWAYS_EAGER=True in the test
    # settings drives the push task inline, but we mock the GitHub PATCH
    # so no real network call is made.
    with patch("ghsa.services.get_client") as mock_get:
        mock_get.return_value.update_advisory_cve.return_value = {"cve_id": "CVE-2026-1234"}
        wf.transition_cve_request(
            task, by=admin, new_status=CveRequestStatus.RESERVED, cve_id="CVE-2026-1234"
        )

    advisory.refresh_from_db()
    assert advisory.assigned_cve_id == "CVE-2026-1234"
    push_tasks = list(GhsaCvePushTask.objects.filter(advisory=advisory))
    assert len(push_tasks) == 1
    assert push_tasks[0].cve_id == "CVE-2026-1234"
    # pytest-django wraps each test in a transaction that's rolled back at
    # teardown, so ``transaction.on_commit`` hooks never fire and the
    # async push stays QUEUED. The actual push-success path is covered in
    # ``test_services.test_push_reserved_cve_marks_success``.
    assert push_tasks[0].status == GhsaCvePushTaskStatus.QUEUED
    assert advisory.ghsa_cve_push_status == GhsaCvePushStatus.PENDING
