from __future__ import annotations

import pytest
from django.urls import reverse

from advisories.models import Advisory
from workflows import services as wf
from workflows.models import (
    CveRequestStatus,
    CveRequestTask,
    ReviewTask,
    ReviewTaskStatus,
)


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    outsider = make_user(email="o@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x", created_by=member)
    return {"admin": admin, "member": member, "outsider": outsider, "advisory": advisory}


# ---- Visibility -----------------------------------------------------------


@pytest.mark.django_db
def test_dashboard_403_for_non_admin(client, setup):
    client.force_login(setup["member"])
    response = client.get(reverse("admin_console:index"))
    assert response.status_code == 403


@pytest.mark.django_db
def test_dashboard_403_for_outsider(client, setup):
    client.force_login(setup["outsider"])
    response = client.get(reverse("admin_console:index"))
    assert response.status_code == 403


@pytest.mark.django_db
def test_dashboard_renders_for_admin(client, setup):
    wf.request_cve(setup["advisory"], by=setup["member"])
    wf.submit_for_review(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:index"))
    assert response.status_code == 200
    body = response.content.decode()
    assert setup["advisory"].advisory_id in body


# ---- CVE actions ----------------------------------------------------------


@pytest.mark.django_db
def test_cve_transition_endpoint_blocked_for_member(client, setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["member"])
    response = client.post(
        reverse("admin_console:cve_transition", args=[task.pk]),
        data={"status": CveRequestStatus.RESERVED, "cve_id": "CVE-2026-1111"},
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_cve_transition_endpoint_reserves_directly(client, setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:cve_transition", args=[task.pk]),
        data={"status": CveRequestStatus.RESERVED, "cve_id": "CVE-2026-1111"},
    )
    assert response.status_code == 200
    task.refresh_from_db()
    assert task.status == CveRequestStatus.RESERVED
    assert task.cve_id == "CVE-2026-1111"


@pytest.mark.django_db
def test_cve_transition_rejects_legacy_in_progress(client, setup):
    """``in_progress`` is no longer a valid CVE status — the endpoint 400s."""
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:cve_transition", args=[task.pk]),
        data={"status": "in_progress"},
    )
    assert response.status_code == 400


@pytest.mark.django_db
def test_cve_reject_without_notes_returns_400(client, setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:cve_transition", args=[task.pk]),
        data={"status": CveRequestStatus.REJECTED},
    )
    assert response.status_code == 400
    task.refresh_from_db()
    assert task.status == CveRequestStatus.QUEUED


@pytest.mark.django_db
def test_cve_reject_with_notes_and_ban_via_endpoint(client, setup):
    from comments.models import AdvisoryComment

    task = wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:cve_transition", args=[task.pk]),
        data={
            "status": CveRequestStatus.REJECTED,
            "notes": "duplicate of an existing CVE",
            "ban_future_requests": "1",
        },
    )
    assert response.status_code == 200
    task.refresh_from_db()
    assert task.status == CveRequestStatus.REJECTED
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].cve_requests_banned is True
    assert AdvisoryComment.objects.filter(
        advisory=setup["advisory"], author=setup["admin"]
    ).exists()


@pytest.mark.django_db
def test_cve_reject_modal_renders_for_admin(client, setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:cve_reject_modal", args=[task.pk]))
    assert response.status_code == 200
    body = response.content.decode()
    assert 'name="notes"' in body
    assert 'name="ban_future_requests"' in body
    assert task.advisory.advisory_id in body


@pytest.mark.django_db
def test_cve_reject_modal_blocked_for_member(client, setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["member"])
    response = client.get(reverse("admin_console:cve_reject_modal", args=[task.pk]))
    assert response.status_code == 403


# ---- Orphan CVE dashboard --------------------------------------------------


def _reserve_and_unassign(setup, cve_id="CVE-2026-1234"):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task, by=setup["admin"], new_status=CveRequestStatus.RESERVED, cve_id=cve_id
    )
    return wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="redo")


@pytest.mark.django_db
def test_cve_assignment_page_lists_orphan_cves_for_admin(client, setup):
    _reserve_and_unassign(setup, cve_id="CVE-2026-0007")
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:cves"))
    assert response.status_code == 200
    body = response.content.decode()
    assert "Orphan CVEs" in body
    assert "CVE-2026-0007" in body


@pytest.mark.django_db
def test_orphan_mark_rejected_endpoint_blocked_for_non_admin(client, setup):
    orphan = _reserve_and_unassign(setup)
    client.force_login(setup["member"])
    response = client.post(
        reverse("admin_console:orphan_mark_rejected", args=[orphan.pk]),
        data={"notes": "n"},
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_orphan_mark_rejected_endpoint_flips_status(client, setup):
    from workflows.models import OrphanCveStatus

    orphan = _reserve_and_unassign(setup)
    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:orphan_mark_rejected", args=[orphan.pk]),
        data={"notes": "MITRE ticket #abc"},
    )
    assert response.status_code == 200
    orphan.refresh_from_db()
    assert orphan.status == OrphanCveStatus.MARKED_REJECTED

    # Second call hits the already-marked guard.
    response = client.post(
        reverse("admin_console:orphan_mark_rejected", args=[orphan.pk]),
        data={"notes": ""},
    )
    assert response.status_code == 400


@pytest.mark.django_db
def test_unassign_cve_endpoint_blocked_for_member(client, setup):
    # Reserve a CVE for the advisory first.
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task, by=setup["admin"], new_status=CveRequestStatus.RESERVED, cve_id="CVE-2026-0099"
    )
    client.force_login(setup["member"])
    response = client.post(
        reverse("advisories:unassign_cve", args=[setup["advisory"].advisory_id]),
        data={"reason": "trying anyway"},
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_unassign_cve_endpoint_admin_happy_path(client, setup):
    from workflows.models import OrphanCve

    task = wf.request_cve(setup["advisory"], by=setup["member"])
    wf.transition_cve_request(
        task, by=setup["admin"], new_status=CveRequestStatus.RESERVED, cve_id="CVE-2026-0099"
    )
    client.force_login(setup["admin"])
    response = client.post(
        reverse("advisories:unassign_cve", args=[setup["advisory"].advisory_id]),
        data={"reason": "wrong advisory"},
    )
    assert response.status_code == 302
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].assigned_cve_id == ""
    assert OrphanCve.objects.filter(cve_id="CVE-2026-0099").exists()


# ---- Workflow action endpoints on the advisory page ----------------------


@pytest.mark.django_db
def test_request_cve_endpoint_blocked_for_outsider(client, setup):
    client.force_login(setup["outsider"])
    response = client.post(reverse("advisories:request_cve", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_request_cve_endpoint_blocked_for_collaborator(client, setup, make_user):
    """A collaborator can edit but must not request a CVE over HTTP — owner-only.
    Regression for advisoryhub--002."""
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    collaborator = make_user(email="collab@example.org")
    grant_to_user(setup["advisory"], collaborator, AccessPermission.COLLABORATOR, by=setup["admin"])
    client.force_login(collaborator)
    response = client.post(reverse("advisories:request_cve", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_request_cve_endpoint_creates_task(client, setup):
    client.force_login(setup["member"])
    response = client.post(reverse("advisories:request_cve", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 302
    assert CveRequestTask.objects.filter(advisory=setup["advisory"]).exists()


@pytest.mark.django_db
def test_submit_review_endpoint_creates_task(client, setup):
    client.force_login(setup["member"])
    response = client.post(
        reverse("advisories:submit_review", args=[setup["advisory"].advisory_id])
    )
    assert response.status_code == 302
    assert ReviewTask.objects.filter(advisory=setup["advisory"]).exists()


# ---- Review decision endpoint on the advisory page -----------------------


@pytest.mark.django_db
def test_review_decide_blocked_for_member(client, setup):
    wf.submit_for_review(setup["advisory"], by=setup["member"])
    client.force_login(setup["member"])
    response = client.post(
        reverse("advisories:review_decide", args=[setup["advisory"].advisory_id]),
        data={"decision": ReviewTaskStatus.APPROVED, "notes": "self approve"},
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_review_decide_approve(client, setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("advisories:review_decide", args=[setup["advisory"].advisory_id]),
        data={"decision": ReviewTaskStatus.APPROVED, "notes": "lgtm"},
    )
    assert response.status_code == 302
    task.refresh_from_db()
    assert task.status == ReviewTaskStatus.APPROVED
    assert task.reviewer == setup["admin"]


@pytest.mark.django_db
def test_review_decide_request_changes_saves_notes(client, setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("advisories:review_decide", args=[setup["advisory"].advisory_id]),
        data={
            "decision": ReviewTaskStatus.CHANGES_REQUESTED,
            "notes": "Please cite the upstream patch.",
        },
    )
    assert response.status_code == 302
    task.refresh_from_db()
    assert task.status == ReviewTaskStatus.CHANGES_REQUESTED
    assert task.decision_notes == "Please cite the upstream patch."


@pytest.mark.django_db
def test_review_decide_rejected_decision_returns_400(client, setup):
    """``rejected`` was removed as a decision; the dispatch dict no longer maps it."""
    wf.submit_for_review(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("advisories:review_decide", args=[setup["advisory"].advisory_id]),
        data={"decision": "rejected"},
    )
    assert response.status_code == 400


@pytest.mark.django_db
def test_review_decide_unknown_decision_returns_400(client, setup):
    wf.submit_for_review(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("advisories:review_decide", args=[setup["advisory"].advisory_id]),
        data={"decision": "abandoned"},
    )
    assert response.status_code == 400


@pytest.mark.django_db
def test_review_decide_404_when_no_open_task(client, setup):
    client.force_login(setup["admin"])
    response = client.post(
        reverse("advisories:review_decide", args=[setup["advisory"].advisory_id]),
        data={"decision": ReviewTaskStatus.APPROVED},
    )
    assert response.status_code == 404


# ---- Project admin --------------------------------------------------------


@pytest.mark.django_db
def test_project_list_requires_admin(client, setup):
    client.force_login(setup["member"])
    response = client.get(reverse("admin_console:project_list"))
    assert response.status_code == 403


@pytest.mark.django_db
def test_project_create_requires_admin(client, setup):
    client.force_login(setup["member"])
    response = client.post(
        reverse("admin_console:project_create"),
        data={
            "slug": "blocked",
            "name": "Blocked",
            "description": "",
            "homepage_url": "",
            "security_team_group_name": "blocked-security",
            "is_mature_publisher": "",
        },
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_project_create_makes_project_and_group(client, setup):
    from django.contrib.auth.models import Group

    from projects.models import Project

    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:project_create"),
        data={
            "slug": "eclipse-foo",
            "name": "Eclipse Foo",
            "description": "Foo project",
            "homepage_url": "",
            "security_team_group_name": "eclipse-foo-security",
            "is_mature_publisher": "on",
        },
    )
    assert response.status_code == 302
    project = Project.objects.get(slug="eclipse-foo")
    assert project.is_mature_publisher is True
    assert project.security_team.name == "eclipse-foo-security"
    # Group was auto-created.
    assert Group.objects.filter(name="eclipse-foo-security").exists()


@pytest.mark.django_db
def test_project_create_reuses_existing_group(client, setup):
    from django.contrib.auth.models import Group

    from projects.models import Project

    existing = Group.objects.create(name="shared-secteam")
    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:project_create"),
        data={
            "slug": "eclipse-bar",
            "name": "Eclipse Bar",
            "description": "",
            "homepage_url": "",
            "security_team_group_name": "shared-secteam",
            "is_mature_publisher": "",
        },
    )
    assert response.status_code == 302
    project = Project.objects.get(slug="eclipse-bar")
    assert project.security_team_id == existing.pk


@pytest.mark.django_db
def test_project_edit_remaps_oidc_group(client, setup):
    from projects.models import Project

    project = Project.objects.get(pk=setup["advisory"].project_id)
    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:project_edit", args=[project.id]),
        data={
            "slug": project.slug,
            "name": project.name,
            "description": project.description,
            "homepage_url": project.homepage_url,
            "security_team_group_name": "remapped-group",
            "is_mature_publisher": "on",
        },
    )
    assert response.status_code == 302
    project.refresh_from_db()
    assert project.security_team.name == "remapped-group"
    assert project.is_mature_publisher is True


@pytest.mark.django_db
def test_project_create_writes_audit_entry(client, setup):
    from audit.models import Action, AuditLogEntry

    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:project_create"),
        data={
            "slug": "eclipse-audited",
            "name": "Eclipse Audited",
            "description": "",
            "homepage_url": "",
            "security_team_group_name": "eclipse-audited-security",
            "is_mature_publisher": "",
        },
    )
    assert response.status_code == 302
    entry = AuditLogEntry.objects.get(action=Action.PROJECT_CREATED)
    assert entry.actor == setup["admin"]
    assert entry.new_value is not None
    assert entry.new_value["slug"] == "eclipse-audited"
    assert entry.new_value["security_team"] == "eclipse-audited-security"
    assert entry.metadata["security_team_group_created"] is True


@pytest.mark.django_db
def test_project_edit_audits_security_team_change(client, setup):
    from audit.models import Action, AuditLogEntry
    from projects.models import Project

    project = Project.objects.get(pk=setup["advisory"].project_id)
    old_group = project.security_team.name
    client.force_login(setup["admin"])
    response = client.post(
        reverse("admin_console:project_edit", args=[project.id]),
        data={
            "slug": project.slug,
            "name": project.name,
            "description": project.description,
            "homepage_url": project.homepage_url,
            "security_team_group_name": "remapped-group",
            "is_mature_publisher": "on" if project.is_mature_publisher else "",
        },
    )
    assert response.status_code == 302
    entry = AuditLogEntry.objects.get(action=Action.PROJECT_UPDATED)
    assert entry.actor == setup["admin"]
    assert entry.previous_value is not None
    assert entry.new_value is not None
    assert entry.previous_value["security_team"] == old_group
    assert entry.new_value["security_team"] == "remapped-group"
    assert "security_team" in entry.metadata["changed"]


@pytest.mark.django_db
def test_project_create_form_renders(client, setup):
    client.force_login(setup["admin"])
    response = client.get(reverse("admin_console:project_create"))
    assert response.status_code == 200
    assert b"security_team_group_name" in response.content


@pytest.mark.django_db
def test_project_edit_shows_security_team_members(client, setup):
    """The project edit page surfaces the live OIDC-group member list (read-only)."""
    from projects.models import Project

    project = Project.objects.get(pk=setup["advisory"].project_id)
    member = setup["member"]  # placed on project `p`'s security team by `setup`
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:project_edit", args=[project.id])).content.decode()
    assert "Security team" in body
    assert member.email in body
    assert reverse("admin_console:user_detail", args=[member.pk]) in body


@pytest.mark.django_db
def test_project_edit_security_team_empty_state(client, setup, make_project):
    """A project whose security-team group has no members shows the empty state."""
    project = make_project("empty-team")  # no team_members
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:project_edit", args=[project.id])).content.decode()
    assert "Security team" in body
    assert "No members." in body


@pytest.mark.django_db
def test_reopen_review_endpoint(client, setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["member"])
    wf.request_changes(task, by=setup["admin"], notes="fix it")
    client.force_login(setup["member"])
    response = client.post(
        reverse("advisories:reopen_review", args=[setup["advisory"].advisory_id])
    )
    assert response.status_code == 302
    setup["advisory"].refresh_from_db()
    from advisories.models import ReviewStatus

    assert setup["advisory"].review_status == ReviewStatus.NONE
