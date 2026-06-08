from __future__ import annotations

import pytest
from django.contrib.auth.models import AnonymousUser

from advisories import permissions as perms
from advisories.models import Advisory, ReviewStatus, State


@pytest.fixture
def world(make_user, make_project, settings):
    """Build a small world for permission tests."""
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"

    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="member@example.org")
    outsider = make_user(email="outsider@example.org")
    other_member = make_user(email="other@example.org")

    project_a = make_project("project-a", team_members=[member])
    project_b = make_project("project-b", team_members=[other_member])

    advisory = Advisory.objects.create(project=project_a, summary="hello")
    return {
        "admin": admin,
        "member": member,
        "outsider": outsider,
        "other_member": other_member,
        "project_a": project_a,
        "project_b": project_b,
        "advisory": advisory,
    }


# ---- resolved_permission ---------------------------------------------------


def test_admin_resolves_as_owner(world):
    assert perms.resolved_permission(world["admin"], world["advisory"]) == "owner"


def test_security_team_member_resolves_as_owner(world):
    assert perms.resolved_permission(world["member"], world["advisory"]) == "owner"


def test_outsider_resolves_to_none(world):
    assert perms.resolved_permission(world["outsider"], world["advisory"]) is None


def test_anonymous_resolves_to_none(world):
    assert perms.resolved_permission(AnonymousUser(), world["advisory"]) is None


@pytest.mark.django_db
def test_published_advisory_not_visible_without_grant(world):
    """Publication state no longer grants implicit access — explicit grant required."""
    a = world["advisory"]
    a.state = State.PUBLISHED
    a.save()
    assert perms.resolved_permission(world["outsider"], a) is None
    assert not perms.can_view(world["outsider"], a)
    assert not perms.can_view(AnonymousUser(), a)


# ---- can_see_user_emails (INV-PRIVACY-4) -----------------------------------


def test_admin_can_see_user_emails(world):
    assert perms.can_see_user_emails(world["admin"], world["advisory"]) is True


def test_security_team_member_can_see_user_emails(world):
    assert perms.can_see_user_emails(world["member"], world["advisory"]) is True


def test_outsider_cannot_see_user_emails(world):
    assert perms.can_see_user_emails(world["outsider"], world["advisory"]) is False


def test_anonymous_cannot_see_user_emails(world):
    assert perms.can_see_user_emails(AnonymousUser(), world["advisory"]) is False


@pytest.mark.django_db
def test_collaborator_and_viewer_cannot_see_user_emails(world, make_user):
    """Owner-only: even a collaborator (who can edit) is blinded to emails."""
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    collaborator = make_user(email="collab@example.org")
    viewer = make_user(email="viewer@example.org")
    grant_to_user(
        world["advisory"], collaborator, AccessPermission.COLLABORATOR, by=world["member"]
    )
    grant_to_user(world["advisory"], viewer, AccessPermission.VIEWER, by=world["member"])

    assert perms.resolved_permission(collaborator, world["advisory"]) == "collaborator"
    assert perms.resolved_permission(viewer, world["advisory"]) == "viewer"
    assert perms.can_see_user_emails(collaborator, world["advisory"]) is False
    assert perms.can_see_user_emails(viewer, world["advisory"]) is False


# ---- can_view --------------------------------------------------------------


def test_anonymous_cannot_view_draft(world):
    assert not perms.can_view(AnonymousUser(), world["advisory"])


def test_outsider_cannot_view_draft(world):
    assert not perms.can_view(world["outsider"], world["advisory"])


def test_team_member_can_view(world):
    assert perms.can_view(world["member"], world["advisory"])


def test_admin_can_view(world):
    assert perms.can_view(world["admin"], world["advisory"])


@pytest.mark.django_db
def test_dismissed_invisible_to_outsider(world):
    a = world["advisory"]
    a.state = State.DISMISSED
    a.dismissed_reason = "n/a"
    a.save()
    assert not perms.can_view(world["outsider"], a)
    assert perms.can_view(world["member"], a)
    assert perms.can_view(world["admin"], a)


# ---- Viewer grants (folded view + comment) ---------------------------------


@pytest.mark.django_db
def test_viewer_grant_unlocks_view(world, make_user):
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    viewer = make_user(email="viewer@example.org")
    assert not perms.can_view(viewer, world["advisory"])
    grant_to_user(world["advisory"], viewer, AccessPermission.VIEWER, by=world["admin"])
    assert perms.can_view(viewer, world["advisory"])


@pytest.mark.django_db
def test_viewer_can_comment(world, make_user):
    """The old `comment` level is folded into `viewer` — anyone who can view
    can also comment."""
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    viewer = make_user(email="viewer@example.org")
    grant_to_user(world["advisory"], viewer, AccessPermission.VIEWER, by=world["admin"])
    assert perms.can_comment(viewer, world["advisory"])


@pytest.mark.django_db
def test_viewer_cannot_edit(world, make_user):
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    viewer = make_user(email="viewer@example.org")
    grant_to_user(world["advisory"], viewer, AccessPermission.VIEWER, by=world["admin"])
    assert not perms.can_edit(viewer, world["advisory"])


# ---- Collaborator grants ---------------------------------------------------


@pytest.mark.django_db
def test_collaborator_can_edit(world, make_user):
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    collab = make_user(email="collab@example.org")
    grant_to_user(world["advisory"], collab, AccessPermission.COLLABORATOR, by=world["admin"])
    assert perms.can_edit(collab, world["advisory"])


@pytest.mark.django_db
def test_collaborator_cannot_grant_access(world, make_user):
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    collab = make_user(email="collab@example.org")
    grant_to_user(world["advisory"], collab, AccessPermission.COLLABORATOR, by=world["admin"])
    assert not perms.can_grant_access(collab, world["advisory"])


@pytest.mark.django_db
def test_collaborator_cannot_dismiss(world, make_user):
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    collab = make_user(email="collab@example.org")
    grant_to_user(world["advisory"], collab, AccessPermission.COLLABORATOR, by=world["admin"])
    assert not perms.can_dismiss(collab, world["advisory"])


@pytest.mark.django_db
def test_collaborator_cannot_submit_for_review(world, make_user):
    """Workflow actions are owner-only — collaborator is strict edit."""
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    collab = make_user(email="collab@example.org")
    grant_to_user(world["advisory"], collab, AccessPermission.COLLABORATOR, by=world["admin"])
    assert not perms.can_submit_for_review(collab, world["advisory"])


@pytest.mark.django_db
def test_collaborator_cannot_request_cve(world, make_user):
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    collab = make_user(email="collab@example.org")
    grant_to_user(world["advisory"], collab, AccessPermission.COLLABORATOR, by=world["admin"])
    assert not perms.can_request_cve(collab, world["advisory"])


# ---- can_edit (security team / admin) --------------------------------------


def test_outsider_cannot_edit(world):
    assert not perms.can_edit(world["outsider"], world["advisory"])


def test_team_member_can_edit(world):
    assert perms.can_edit(world["member"], world["advisory"])


def test_admin_can_edit(world):
    assert perms.can_edit(world["admin"], world["advisory"])


@pytest.mark.django_db
def test_edit_frozen_during_review(world):
    a = world["advisory"]
    a.review_status = ReviewStatus.SUBMITTED
    a.save()
    assert not perms.can_edit(world["member"], a)
    # Admins can still edit (e.g. to fix typos before approval if needed)
    assert perms.can_edit(world["admin"], a)


# ---- Owner-only governance actions on security-team members ----------------


def test_team_member_can_grant_access(world):
    assert perms.can_grant_access(world["member"], world["advisory"])


def test_team_member_can_submit_for_review(world):
    assert perms.can_submit_for_review(world["member"], world["advisory"])


def test_admin_cannot_submit_for_review(world):
    """Admins are reviewers, not submitters — even though resolved_permission is 'owner'."""
    assert perms.resolved_permission(world["admin"], world["advisory"]) == "owner"
    assert not perms.can_submit_for_review(world["admin"], world["advisory"])


def test_team_member_can_dismiss(world):
    assert perms.can_dismiss(world["member"], world["advisory"])


# ---- can_change_project ----------------------------------------------------


def test_cannot_change_project_to_one_user_doesnt_belong(world):
    assert not perms.can_change_project(world["member"], world["advisory"], world["project_b"])


def test_admin_can_change_project_anywhere(world):
    assert perms.can_change_project(world["admin"], world["advisory"], world["project_b"])


@pytest.mark.django_db
def test_member_of_destination_can_change_project(world, make_user):
    # User belongs to security teams of BOTH project_a and project_b
    user = make_user(
        email="dual@example.org",
        groups=[
            world["project_a"].security_team.name,
            world["project_b"].security_team.name,
        ],
    )
    assert perms.can_change_project(user, world["advisory"], world["project_b"])


# ---- can_publish -----------------------------------------------------------


def test_publish_blocked_for_outsider(world):
    assert not perms.can_publish(world["outsider"], world["advisory"])


def test_publish_blocked_for_member_of_non_mature_unapproved(world):
    assert not perms.can_publish(world["member"], world["advisory"])


@pytest.mark.django_db
def test_publish_allowed_for_member_of_mature_project(world):
    p = world["advisory"].project
    p.is_mature_publisher = True
    p.save()
    assert perms.can_publish(world["member"], world["advisory"])


@pytest.mark.django_db
def test_publish_allowed_after_review_approved(world):
    a = world["advisory"]
    a.review_status = ReviewStatus.APPROVED
    a.save()
    assert perms.can_publish(world["member"], a)


def test_publish_allowed_for_admin(world):
    assert perms.can_publish(world["admin"], world["advisory"])


@pytest.mark.django_db
def test_publish_blocked_for_dismissed(world):
    a = world["advisory"]
    a.state = State.DISMISSED
    a.dismissed_reason = "x"
    a.save()
    assert not perms.can_publish(world["admin"], a)


@pytest.mark.django_db
def test_publish_blocked_during_pending_review_for_admin(world):
    a = world["advisory"]
    a.review_status = ReviewStatus.SUBMITTED
    a.save()
    assert not perms.can_publish(world["admin"], a)


@pytest.mark.django_db
def test_publish_blocked_during_pending_review_for_mature_member(world):
    a = world["advisory"]
    p = a.project
    p.is_mature_publisher = True
    p.save()
    a.review_status = ReviewStatus.SUBMITTED
    a.save()
    assert not perms.can_publish(world["member"], a)


# ---- can_withdraw_review ---------------------------------------------------


@pytest.mark.django_db
def test_can_withdraw_review_owner(world):
    a = world["advisory"]
    a.review_status = ReviewStatus.SUBMITTED
    a.save()
    # Non-mature project: owner can still withdraw.
    assert perms.can_withdraw_review(world["member"], a)
    # Mature publisher: owner can also withdraw.
    p = a.project
    p.is_mature_publisher = True
    p.save()
    assert perms.can_withdraw_review(world["member"], a)


@pytest.mark.django_db
def test_can_withdraw_review_only_when_submitted(world):
    a = world["advisory"]
    for status in (
        ReviewStatus.NONE,
        ReviewStatus.APPROVED,
        ReviewStatus.CHANGES_REQUESTED,
    ):
        a.review_status = status
        a.save()
        assert not perms.can_withdraw_review(world["member"], a)


@pytest.mark.django_db
def test_admin_cannot_withdraw_review(world):
    """Admins are reviewers, not submitters — withdraw is hidden for them."""
    a = world["advisory"]
    a.review_status = ReviewStatus.SUBMITTED
    a.save()
    # The admin resolves as 'owner', but withdraw is still blocked.
    assert perms.resolved_permission(world["admin"], a) == "owner"
    assert not perms.can_withdraw_review(world["admin"], a)


# ---- can_revoke_approval ---------------------------------------------------


@pytest.mark.django_db
def test_can_revoke_approval_admin_only_when_approved(world):
    a = world["advisory"]
    a.review_status = ReviewStatus.APPROVED
    a.save()
    assert perms.can_revoke_approval(world["admin"], a)
    # Non-admin owner (security-team member) is blocked.
    assert not perms.can_revoke_approval(world["member"], a)
    # Outsider blocked.
    assert not perms.can_revoke_approval(world["outsider"], a)
    # Status other than APPROVED → blocked even for admin.
    for status in (
        ReviewStatus.NONE,
        ReviewStatus.SUBMITTED,
        ReviewStatus.CHANGES_REQUESTED,
    ):
        a.review_status = status
        a.save()
        assert not perms.can_revoke_approval(world["admin"], a)


@pytest.mark.django_db
def test_can_withdraw_review_outsider_blocked(world):
    a = world["advisory"]
    a.review_status = ReviewStatus.SUBMITTED
    a.save()
    assert not perms.can_withdraw_review(world["outsider"], a)
    assert not perms.can_withdraw_review(AnonymousUser(), a)


@pytest.mark.django_db
def test_withdraw_does_not_unlock_publish_on_non_mature(world):
    """After withdrawing, a non-mature project owner still can't publish."""
    a = world["advisory"]
    a.review_status = ReviewStatus.NONE  # state after a withdraw
    a.save()
    assert not perms.can_publish(world["member"], a)


# ---- can_create_advisory_for_project ---------------------------------------


def test_member_can_create_for_own_project(world):
    assert perms.can_create_advisory_for_project(world["member"], world["project_a"])


def test_member_cannot_create_for_other_project(world):
    assert not perms.can_create_advisory_for_project(world["member"], world["project_b"])


def test_admin_can_create_for_any_project(world):
    assert perms.can_create_advisory_for_project(world["admin"], world["project_b"])


# ---- can_author_any_advisory -----------------------------------------------


def test_admin_can_author_any_advisory(world):
    assert perms.can_author_any_advisory(world["admin"])


def test_team_member_can_author_any_advisory(world):
    assert perms.can_author_any_advisory(world["member"])


def test_outsider_cannot_author_any_advisory(world):
    assert not perms.can_author_any_advisory(world["outsider"])


def test_anonymous_cannot_author_any_advisory():
    assert not perms.can_author_any_advisory(AnonymousUser())


def test_user_property_mirrors_can_author_any_advisory(world):
    assert world["member"].can_author_advisories is True
    assert world["outsider"].can_author_advisories is False


# ---- can_review ------------------------------------------------------------


def test_only_admin_can_review(world):
    assert perms.can_review(world["admin"])
    assert not perms.can_review(world["member"])
    assert not perms.can_review(world["outsider"])
    assert not perms.can_review(AnonymousUser())
