"""Granting / revoking advisory access and redeeming invitations.

All callers go through these helpers so that:

* every access change emits an audit entry,
* a notification email is dispatched if appropriate (Phase B),
* invitation redemption uses case-insensitive email matching enforced
  here — never accept the email from form data alone.
"""

from __future__ import annotations

from collections.abc import Iterable

from django.contrib.auth.models import Group
from django.db import transaction
from django.utils import timezone

from accounts.models import User
from advisories.models import Advisory
from audit.models import Action
from audit.services import record
from common.enqueue import safe_enqueue
from common.users import actor_or_none

from .models import (
    AdvisoryAccessGrant,
    PendingInvitation,
    Permission,
    PrincipalType,
    _default_invitation_expiry,
)


def _validate_grantable_permission(permission: str) -> None:
    if permission == "owner":
        raise ValueError(
            "Owner is not grantable: it derives from project security team membership."
        )
    if permission not in Permission.values:
        raise ValueError(f"Unknown permission {permission!r}")


# ---- Grants ---------------------------------------------------------------


@transaction.atomic
def grant_to_user(
    advisory: Advisory, user: User, permission: str, *, by: User | None
) -> AdvisoryAccessGrant:
    return _set_grant(advisory, PrincipalType.USER, user.pk, permission, by=by)


@transaction.atomic
def grant_to_group(
    advisory: Advisory, group: Group, permission: str, *, by: User | None
) -> AdvisoryAccessGrant:
    return _set_grant(advisory, PrincipalType.GROUP, group.pk, permission, by=by)


def _set_grant(
    advisory: Advisory,
    principal_type: str,
    principal_id: int,
    permission: str,
    *,
    by: User | None,
) -> AdvisoryAccessGrant:
    _validate_grantable_permission(permission)
    actor = actor_or_none(by)
    existing = AdvisoryAccessGrant.objects.filter(
        advisory=advisory, principal_type=principal_type, principal_id=principal_id
    ).first()
    if existing is None:
        grant = AdvisoryAccessGrant.objects.create(
            advisory=advisory,
            principal_type=principal_type,
            principal_id=principal_id,
            permission=permission,
            created_by=actor,
        )
        record(
            action=Action.ACCESS_GRANTED,
            actor=by,
            advisory=advisory,
            new_value={
                "principal_type": principal_type,
                "principal_id": principal_id,
                "permission": permission,
            },
        )
        return grant

    if existing.permission == permission:
        return existing

    previous = existing.permission
    existing.permission = permission
    existing.save(update_fields=["permission"])
    record(
        action=Action.ACCESS_GRANTED,
        actor=by,
        advisory=advisory,
        previous_value={"permission": previous},
        new_value={
            "principal_type": principal_type,
            "principal_id": principal_id,
            "permission": permission,
        },
        metadata={"updated": True},
    )
    return existing


@transaction.atomic
def revoke(grant: AdvisoryAccessGrant, *, by: User | None) -> None:
    record(
        action=Action.ACCESS_REVOKED,
        actor=by,
        advisory=grant.advisory,
        previous_value={
            "principal_type": grant.principal_type,
            "principal_id": grant.principal_id,
            "permission": grant.permission,
        },
    )
    grant.delete()


# ---- Invitations ----------------------------------------------------------


@transaction.atomic
def invite_email(
    advisory: Advisory, email: str, permission: str, *, by: User | None
) -> PendingInvitation:
    """Create a PendingInvitation. If the email already belongs to a user,
    the grant is created immediately instead.
    """
    _validate_grantable_permission(permission)
    email = email.strip()
    existing = User.objects.filter(email__iexact=email).first()
    if existing is not None:
        grant_to_user(advisory, existing, permission, by=by)
        # Return a transient PendingInvitation marked redeemed so callers
        # have a uniform return type. We don't persist it.
        return PendingInvitation(
            advisory=advisory,
            email=email,
            permission=permission,
            redeemed_at=timezone.now(),
            redeemed_by=existing,
        )
    invitation = PendingInvitation.objects.create(
        advisory=advisory,
        email=email,
        permission=permission,
        created_by=actor_or_none(by),
    )
    record(
        action=Action.INVITATION_CREATED,
        actor=by,
        advisory=advisory,
        new_value={"email": email, "permission": permission},
    )
    return invitation


@transaction.atomic
def redeem_invitations_for_user(user: User) -> list[AdvisoryAccessGrant]:
    """Redeem any pending invitations matching the user's authenticated email.

    Match is case-insensitive on email. Invitations created for a different
    email cannot be redeemed by this user — even if a token is leaked, it
    only redeems for its target email.
    """
    if not user or not user.email:
        return []
    pending = PendingInvitation.objects.filter(email__iexact=user.email, redeemed_at__isnull=True)
    grants: list[AdvisoryAccessGrant] = []
    now = timezone.now()
    for invite in pending.select_related("advisory"):
        if invite.is_expired(now=now):
            continue
        grant = grant_to_user(invite.advisory, user, invite.permission, by=invite.created_by)
        invite.redeemed_at = now
        invite.redeemed_by = user
        invite.save(update_fields=["redeemed_at", "redeemed_by"])
        record(
            action=Action.INVITATION_REDEEMED,
            actor=user,
            advisory=invite.advisory,
            new_value={"email": user.email, "permission": invite.permission},
        )
        grants.append(grant)
    return grants


@transaction.atomic
def update_invitation_permission(
    invitation: PendingInvitation, permission: str, *, by: User | None
) -> PendingInvitation:
    _validate_grantable_permission(permission)
    if invitation.permission == permission:
        return invitation
    previous = invitation.permission
    invitation.permission = permission
    invitation.save(update_fields=["permission"])
    record(
        action=Action.INVITATION_CREATED,
        actor=by,
        advisory=invitation.advisory,
        previous_value={"permission": previous},
        new_value={"email": invitation.email, "permission": permission},
        metadata={"updated": True},
    )
    return invitation


@transaction.atomic
def revoke_invitation(invitation: PendingInvitation, *, by: User | None) -> None:
    record(
        action=Action.INVITATION_REVOKED,
        actor=by,
        advisory=invitation.advisory,
        previous_value={"email": invitation.email, "permission": invitation.permission},
    )
    invitation.delete()


@transaction.atomic
def resend_invitation(invitation: PendingInvitation, *, by: User | None) -> None:
    """Re-send a pending invitation email and refresh its expiry window.

    Resetting ``expires_at`` to a fresh window (the same default applied at
    creation) makes the re-sent link redeemable again even if the original had
    lapsed — see INV-ACCESS-3. The token is unchanged. Already-redeemed
    invitations are a no-op (the grant is held; re-sending would only confuse).
    """
    if invitation.redeemed_at is not None:
        return
    invitation.expires_at = _default_invitation_expiry()
    invitation.save(update_fields=["expires_at"])
    record(
        action=Action.INVITATION_RESENT,
        actor=by,
        advisory=invitation.advisory,
        new_value={
            "email": invitation.email,
            "permission": invitation.permission,
            "expires_at": invitation.expires_at.isoformat(),
        },
    )
    # Dispatch after commit, mirroring access.views._queue_invite_email_for_latest.
    # Deferred import keeps the access ↔ notifications dependency one-directional.
    from notifications.tasks import send_invitation_email

    transaction.on_commit(lambda: safe_enqueue(send_invitation_email, invitation.pk))


def list_active_grants(advisory: Advisory) -> Iterable[AdvisoryAccessGrant]:
    return advisory.access_grants.all().order_by("principal_type", "principal_id")


def list_pending_invitations(advisory: Advisory) -> Iterable[PendingInvitation]:
    return advisory.pending_invitations.filter(redeemed_at__isnull=True).order_by("email")


def groups_grantable_by(user: User) -> list[Group]:
    """Groups the user is allowed to suggest in an access-grant autocomplete.

    Admins see all groups; everyone else sees only the groups they belong to.
    """
    from advisories.permissions import is_global_admin

    if is_global_admin(user):
        return list(Group.objects.all().order_by("name"))
    return list(user.groups.all().order_by("name"))
