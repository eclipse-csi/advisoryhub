from __future__ import annotations

import json
from datetime import timedelta

import pytest
from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils import timezone

from access import services
from access.models import AdvisoryAccessGrant, PendingInvitation, Permission, PrincipalType
from access.services import (
    grant_to_group,
    grant_to_user,
    invite_email,
    redeem_invitations_for_user,
    resend_invitation,
    revoke,
)
from advisories import permissions as perms
from advisories.models import Advisory
from audit.models import Action, AuditLogEntry


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    member = make_user(email="member@example.org")
    make_project("eclipse-jetty", team_members=[member])
    other_project = make_project("eclipse-other")
    advisory = Advisory.objects.create(project=other_project, summary="hello")
    return {"member": member, "advisory": advisory}


# ---- grant_to_user --------------------------------------------------------


@pytest.mark.django_db
def test_grant_to_user_creates_grant_and_audit(setup, make_user):
    user = make_user(email="x@example.org")
    grant = grant_to_user(setup["advisory"], user, Permission.VIEWER, by=setup["member"])
    assert grant.principal_type == PrincipalType.USER
    assert grant.principal_id == user.pk
    assert AuditLogEntry.objects.filter(action=Action.ACCESS_GRANTED).exists()


@pytest.mark.django_db
def test_grant_then_view_passes(setup, make_user):
    user = make_user(email="x@example.org")
    assert not perms.can_view(user, setup["advisory"])
    grant_to_user(setup["advisory"], user, Permission.VIEWER, by=setup["member"])
    assert perms.can_view(user, setup["advisory"])


@pytest.mark.django_db
def test_grant_viewer_unlocks_comment(setup, make_user):
    """The old `comment` level was folded into `viewer`."""
    user = make_user(email="x@example.org")
    grant_to_user(setup["advisory"], user, Permission.VIEWER, by=setup["member"])
    assert perms.can_comment(user, setup["advisory"])
    assert not perms.can_edit(user, setup["advisory"])


@pytest.mark.django_db
def test_grant_collaborator_unlocks_edit(setup, make_user):
    user = make_user(email="x@example.org")
    grant_to_user(setup["advisory"], user, Permission.COLLABORATOR, by=setup["member"])
    assert perms.can_edit(user, setup["advisory"])


@pytest.mark.django_db
def test_grant_owner_rejected_at_service_layer(setup, make_user):
    """Owner is derived, not grantable — the service must reject it."""
    user = make_user(email="x@example.org")
    with pytest.raises(ValueError, match="not grantable"):
        grant_to_user(setup["advisory"], user, "owner", by=setup["member"])


@pytest.mark.django_db
def test_grant_to_group_via_membership(setup, make_user):
    group = Group.objects.create(name="ad-hoc-reviewers")
    user = make_user(email="x@example.org")
    user.groups.add(group)
    assert not perms.can_view(user, setup["advisory"])
    grant_to_group(setup["advisory"], group, Permission.VIEWER, by=setup["member"])
    assert perms.can_view(user, setup["advisory"])


@pytest.mark.django_db
def test_revoke_removes_access_immediately(setup, make_user):
    user = make_user(email="x@example.org")
    g = grant_to_user(setup["advisory"], user, Permission.VIEWER, by=setup["member"])
    assert perms.can_view(user, setup["advisory"])
    revoke(g, by=setup["member"])
    assert not perms.can_view(user, setup["advisory"])
    assert AuditLogEntry.objects.filter(action=Action.ACCESS_REVOKED).exists()


@pytest.mark.django_db
def test_grant_upgrade_records_audit_with_previous_value(setup, make_user):
    user = make_user(email="x@example.org")
    grant_to_user(setup["advisory"], user, Permission.VIEWER, by=setup["member"])
    AuditLogEntry.objects.all().count()
    grant_to_user(setup["advisory"], user, Permission.COLLABORATOR, by=setup["member"])
    audit = AuditLogEntry.objects.filter(
        action=Action.ACCESS_GRANTED, metadata__updated=True
    ).first()
    assert audit is not None
    assert audit.previous_value == {"permission": Permission.VIEWER}


# ---- Invitations ----------------------------------------------------------


@pytest.mark.django_db
def test_invite_email_for_existing_user_grants_immediately(setup, make_user):
    existing = make_user(email="x@example.org")
    invitation = invite_email(
        setup["advisory"], "X@example.org", Permission.VIEWER, by=setup["member"]
    )
    assert invitation.redeemed_at is not None  # transient redeemed marker
    assert AdvisoryAccessGrant.objects.filter(
        advisory=setup["advisory"], principal_type=PrincipalType.USER, principal_id=existing.pk
    ).exists()


@pytest.mark.django_db
def test_invite_email_for_new_user_creates_invitation_and_audit(setup):
    invitation = invite_email(
        setup["advisory"], "newcomer@example.org", Permission.VIEWER, by=setup["member"]
    )
    assert invitation.pk is not None
    assert AuditLogEntry.objects.filter(action=Action.INVITATION_CREATED).exists()


@pytest.mark.django_db
def test_invite_email_rejects_owner(setup):
    with pytest.raises(ValueError, match="not grantable"):
        invite_email(setup["advisory"], "newcomer@example.org", "owner", by=setup["member"])


@pytest.mark.django_db
def test_invitation_cannot_be_redeemed_by_different_email(setup, make_user):
    invite_email(setup["advisory"], "wanted@example.org", Permission.VIEWER, by=setup["member"])
    other = make_user(email="someone-else@example.org")
    grants = redeem_invitations_for_user(other)
    assert grants == []
    assert not perms.can_view(other, setup["advisory"])


@pytest.mark.django_db
def test_invitation_redemption_is_case_insensitive(setup, make_user):
    invite_email(setup["advisory"], "Wanted@Example.ORG", Permission.VIEWER, by=setup["member"])
    new_user = make_user(email="wanted@example.org")
    grants = redeem_invitations_for_user(new_user)
    assert len(grants) == 1
    assert perms.can_view(new_user, setup["advisory"])
    invite = PendingInvitation.objects.get(email__iexact="wanted@example.org")
    assert invite.redeemed_at is not None


@pytest.mark.django_db
def test_invitation_expiry_blocks_redemption(setup, make_user):
    invite = PendingInvitation.objects.create(
        advisory=setup["advisory"],
        email="late@example.org",
        permission=Permission.VIEWER,
    )
    invite.expires_at = timezone.now() - timedelta(seconds=1)
    invite.save(update_fields=["expires_at"])
    user = make_user(email="late@example.org")
    grants = redeem_invitations_for_user(user)
    assert grants == []


@pytest.mark.django_db
def test_invitation_records_redemption_audit(setup, make_user):
    invite_email(setup["advisory"], "newcomer@example.org", Permission.VIEWER, by=setup["member"])
    user = make_user(email="newcomer@example.org")
    redeem_invitations_for_user(user)
    assert AuditLogEntry.objects.filter(
        action=Action.INVITATION_REDEEMED, advisory=setup["advisory"]
    ).exists()


# ---- resend_invitation ----------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_resend_invitation_refreshes_expiry_audits_and_emails(setup):
    from django.core import mail

    invite = PendingInvitation.objects.create(
        advisory=setup["advisory"],
        email="late@example.org",
        permission=Permission.VIEWER,
    )
    # Force it stale so the refresh is observable.
    stale = timezone.now() - timedelta(days=1)
    invite.expires_at = stale
    invite.save(update_fields=["expires_at"])
    mail.outbox.clear()

    resend_invitation(invite, by=setup["member"])

    invite.refresh_from_db()
    assert invite.expires_at > timezone.now()  # INV-ACCESS-3: link is redeemable again
    assert AuditLogEntry.objects.filter(
        action=Action.INVITATION_RESENT, advisory=setup["advisory"]
    ).exists()
    assert any("late@example.org" in m.to for m in mail.outbox)


@pytest.mark.django_db(transaction=True)
def test_resend_invitation_noop_when_redeemed(setup, make_user):
    from django.core import mail

    redeemer = make_user(email="done@example.org")
    invite = PendingInvitation.objects.create(
        advisory=setup["advisory"],
        email="done@example.org",
        permission=Permission.VIEWER,
        redeemed_at=timezone.now(),
        redeemed_by=redeemer,
    )
    original_expiry = invite.expires_at
    mail.outbox.clear()

    resend_invitation(invite, by=setup["member"])

    invite.refresh_from_db()
    assert invite.expires_at == original_expiry
    assert not AuditLogEntry.objects.filter(action=Action.INVITATION_RESENT).exists()
    assert mail.outbox == []


# ---- Batch save endpoint --------------------------------------------------


@pytest.fixture
def batch_setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    member = make_user(email="member@example.org")
    project = make_project("eclipse-foo", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="hello")
    return {"member": member, "project": project, "advisory": advisory}


def _post_batch(client, advisory, payload):
    return client.post(
        reverse("access:batch_save", args=[advisory.advisory_id]),
        data=json.dumps(payload),
        content_type="application/json",
    )


@pytest.mark.django_db
def test_batch_requires_grant_permission(client, batch_setup, make_user):
    outsider = make_user(email="o@example.org")
    client.force_login(outsider)
    response = _post_batch(client, batch_setup["advisory"], {"grants_add": []})
    assert response.status_code == 403


@pytest.mark.django_db
def test_batch_add_user_creates_grant(client, batch_setup, make_user):
    target = make_user(email="x@example.org")
    client.force_login(batch_setup["member"])
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {"grants_add": [{"principal": target.email, "permission": "viewer"}]},
    )
    assert response.status_code == 200
    assert AdvisoryAccessGrant.objects.filter(
        advisory=batch_setup["advisory"],
        principal_type=PrincipalType.USER,
        principal_id=target.pk,
        permission=Permission.VIEWER,
    ).exists()


@pytest.mark.django_db
def test_batch_add_unknown_email_creates_invitation(client, batch_setup):
    client.force_login(batch_setup["member"])
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {"grants_add": [{"principal": "newcomer@example.org", "permission": "viewer"}]},
    )
    assert response.status_code == 200
    assert PendingInvitation.objects.filter(
        advisory=batch_setup["advisory"], email="newcomer@example.org"
    ).exists()


@pytest.mark.django_db
def test_batch_add_group_requires_membership(client, batch_setup):
    # Group exists but the granting user is not a member → rejected.
    Group.objects.create(name="ad-hoc-reviewers")
    client.force_login(batch_setup["member"])
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {"grants_add": [{"principal": "@ad-hoc-reviewers", "permission": "viewer"}]},
    )
    assert response.status_code == 400
    assert (
        AdvisoryAccessGrant.objects.filter(
            advisory=batch_setup["advisory"], principal_type=PrincipalType.GROUP
        ).count()
        == 0
    )


@pytest.mark.django_db
def test_batch_add_group_when_member_succeeds(client, batch_setup):
    group = Group.objects.create(name="reviewers")
    batch_setup["member"].groups.add(group)
    client.force_login(batch_setup["member"])
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {"grants_add": [{"principal": "@reviewers", "permission": "collaborator"}]},
    )
    assert response.status_code == 200
    assert AdvisoryAccessGrant.objects.filter(
        advisory=batch_setup["advisory"],
        principal_type=PrincipalType.GROUP,
        principal_id=group.pk,
        permission=Permission.COLLABORATOR,
    ).exists()


@pytest.mark.django_db
def test_batch_admin_can_grant_any_group(client, batch_setup, make_user, settings):
    admin_group, _ = Group.objects.get_or_create(name=settings.OIDC_ADMIN_GROUP)
    admin = make_user(email="admin@example.org")
    admin.groups.add(admin_group)
    other_group = Group.objects.create(name="strangers")
    client.force_login(admin)
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {"grants_add": [{"principal": "@strangers", "permission": "viewer"}]},
    )
    assert response.status_code == 200
    assert AdvisoryAccessGrant.objects.filter(
        advisory=batch_setup["advisory"],
        principal_type=PrincipalType.GROUP,
        principal_id=other_group.pk,
    ).exists()


@pytest.mark.django_db
def test_batch_rejects_owner_permission(client, batch_setup, make_user):
    """Owner is not grantable — the batch endpoint must reject it with a 400."""
    target = make_user(email="x@example.org")
    client.force_login(batch_setup["member"])
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {"grants_add": [{"principal": target.email, "permission": "owner"}]},
    )
    assert response.status_code == 400
    body = response.json()
    assert any("not grantable" in e for e in body["errors"])
    assert not AdvisoryAccessGrant.objects.filter(
        advisory=batch_setup["advisory"], principal_id=target.pk
    ).exists()


@pytest.mark.django_db
def test_batch_update_changes_permission(client, batch_setup, make_user):
    target = make_user(email="x@example.org")
    grant = grant_to_user(
        batch_setup["advisory"], target, Permission.VIEWER, by=batch_setup["member"]
    )
    client.force_login(batch_setup["member"])
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {"grants_update": [{"id": grant.pk, "permission": "collaborator"}]},
    )
    assert response.status_code == 200
    grant.refresh_from_db()
    assert grant.permission == Permission.COLLABORATOR


@pytest.mark.django_db
def test_batch_update_invitation_permission(client, batch_setup):
    invite = invite_email(
        batch_setup["advisory"], "x@example.org", Permission.VIEWER, by=batch_setup["member"]
    )
    client.force_login(batch_setup["member"])
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {"invitations_update": [{"id": invite.pk, "permission": "collaborator"}]},
    )
    assert response.status_code == 200
    invite.refresh_from_db()
    assert invite.permission == Permission.COLLABORATOR


@pytest.mark.django_db
def test_batch_revoke_grant(client, batch_setup, make_user):
    target = make_user(email="x@example.org")
    grant = grant_to_user(
        batch_setup["advisory"], target, Permission.VIEWER, by=batch_setup["member"]
    )
    client.force_login(batch_setup["member"])
    response = _post_batch(client, batch_setup["advisory"], {"grants_revoke": [grant.pk]})
    assert response.status_code == 200
    assert not AdvisoryAccessGrant.objects.filter(pk=grant.pk).exists()


@pytest.mark.django_db
def test_batch_revoke_invitation(client, batch_setup):
    invite = invite_email(
        batch_setup["advisory"], "x@example.org", Permission.VIEWER, by=batch_setup["member"]
    )
    client.force_login(batch_setup["member"])
    response = _post_batch(client, batch_setup["advisory"], {"invitations_revoke": [invite.pk]})
    assert response.status_code == 200
    assert not PendingInvitation.objects.filter(pk=invite.pk).exists()
    assert AuditLogEntry.objects.filter(action=Action.INVITATION_REVOKED).exists()


@pytest.mark.django_db
def test_batch_rolls_back_on_validation_error(client, batch_setup, make_user):
    target = make_user(email="x@example.org")
    client.force_login(batch_setup["member"])
    # One valid add, one bad permission — entire batch must be rejected.
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {
            "grants_add": [
                {"principal": target.email, "permission": "viewer"},
                {"principal": "another@example.org", "permission": "bogus"},
            ]
        },
    )
    assert response.status_code == 400
    assert not AdvisoryAccessGrant.objects.filter(
        advisory=batch_setup["advisory"], principal_id=target.pk
    ).exists()


@pytest.mark.django_db
def test_batch_applies_combined_ops(client, batch_setup, make_user):
    keeper = make_user(email="keeper@example.org")
    goner = make_user(email="goner@example.org")
    grant_to_user(batch_setup["advisory"], goner, Permission.VIEWER, by=batch_setup["member"])
    keep_grant = grant_to_user(
        batch_setup["advisory"], keeper, Permission.VIEWER, by=batch_setup["member"]
    )
    to_revoke = AdvisoryAccessGrant.objects.get(
        advisory=batch_setup["advisory"], principal_id=goner.pk
    )
    client.force_login(batch_setup["member"])
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {
            "grants_add": [{"principal": "newcomer@example.org", "permission": "viewer"}],
            "grants_update": [{"id": keep_grant.pk, "permission": "collaborator"}],
            "grants_revoke": [to_revoke.pk],
        },
    )
    assert response.status_code == 200
    keep_grant.refresh_from_db()
    assert keep_grant.permission == Permission.COLLABORATOR
    assert not AdvisoryAccessGrant.objects.filter(pk=to_revoke.pk).exists()
    assert PendingInvitation.objects.filter(
        advisory=batch_setup["advisory"], email="newcomer@example.org"
    ).exists()


# ---- Pinned project-security-team row -------------------------------------


@pytest.mark.django_db
def test_panel_pins_project_security_team_in_owners_section(client, batch_setup):
    client.force_login(batch_setup["member"])
    response = client.get(reverse("access:panel", args=[batch_setup["advisory"].advisory_id]))
    assert response.status_code == 200
    html = response.content.decode()
    team_name = batch_setup["project"].security_team.name
    assert "access-row--locked" in html
    assert f"@{team_name}" in html
    # Locked rows must not be draggable and must not expose a remove control.
    assert 'draggable="false"' in html
    # Quick sanity check: no remove button for the pinned row.
    locked_fragment = html.split("access-row--locked", 1)[1].split("</li>", 1)[0]
    assert "access-row__remove" not in locked_fragment


@pytest.mark.django_db
def test_panel_hides_explicit_grant_for_project_security_team(batch_setup):
    # Manually create an explicit grant for the project's security_team group
    # (would normally be blocked by batch_save; create directly via the model).
    AdvisoryAccessGrant.objects.create(
        advisory=batch_setup["advisory"],
        principal_type=PrincipalType.GROUP,
        principal_id=batch_setup["project"].security_team_id,
        permission=Permission.COLLABORATOR,
    )
    from access.views import OWNER_SECTION_KEY, _panel_context

    ctx = _panel_context(batch_setup["advisory"], batch_setup["member"])
    owners_section = next(s for s in ctx["sections"] if s["permission"] == OWNER_SECTION_KEY)
    team_name = batch_setup["project"].security_team.name
    # The pinned locked row should be the only entry for the security team.
    matching = [r for r in owners_section["rows"] if r["label"] == f"@{team_name}"]
    assert len(matching) == 1
    assert matching[0].get("locked") is True
    # The explicit grant must not appear as a separate row in any section.
    for section in ctx["sections"]:
        assert not any(
            r.get("type") == "grant" and r["label"] == f"@{team_name}" for r in section["rows"]
        )


@pytest.mark.django_db
def test_batch_rejects_explicit_grant_for_project_security_team(client, batch_setup):
    client.force_login(batch_setup["member"])
    team_name = batch_setup["project"].security_team.name
    # The granting member is in the team group, so it passes the
    # grantable-groups check and reaches the security-team guard.
    response = _post_batch(
        client,
        batch_setup["advisory"],
        {"grants_add": [{"principal": f"@{team_name}", "permission": "collaborator"}]},
    )
    assert response.status_code == 400
    body = response.json()
    assert any("project security team" in e for e in body["errors"])
    assert not AdvisoryAccessGrant.objects.filter(
        advisory=batch_setup["advisory"],
        principal_type=PrincipalType.GROUP,
        principal_id=batch_setup["project"].security_team_id,
    ).exists()


# ---- Group autocomplete ---------------------------------------------------


@pytest.mark.django_db
def test_groups_grantable_by_member_lists_their_groups(make_user):
    user = make_user(email="u@example.org")
    in_group = Group.objects.create(name="reviewers")
    Group.objects.create(name="not-mine")
    user.groups.add(in_group)
    names = [g.name for g in services.groups_grantable_by(user)]
    assert "reviewers" in names
    assert "not-mine" not in names


@pytest.mark.django_db
def test_groups_grantable_by_admin_lists_all(make_user, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin_group, _ = Group.objects.get_or_create(name=settings.OIDC_ADMIN_GROUP)
    admin = make_user(email="a@example.org")
    admin.groups.add(admin_group)
    Group.objects.create(name="reviewers")
    Group.objects.create(name="strangers")
    names = [g.name for g in services.groups_grantable_by(admin)]
    assert "reviewers" in names
    assert "strangers" in names
