"""Account-level admin services: ban / unban a user (INV-AUTH-8).

A ban disables an account locally: the enforcement switch is the inherited
``User.is_active`` flag (the OIDC callback view refuses login when it is False,
and ``AdvisoryHubOIDCBackend.get_user`` drops a live session on the next
request). These services keep ``is_active`` in lockstep with the ban metadata
(``banned_at`` / ``banned_by`` / ``ban_reason``) and are the *only* place that
toggles ``is_active``.

They mutate model state only and are idempotent; the calling view records the
durable audit entry (so the acting admin's IP / user-agent are captured). See
``docs/specification/permissions.md`` and INV-AUTH-8 in ``invariant.md``.
"""

from __future__ import annotations

from django.utils import timezone

from .models import User


def ban_user(user: User, *, by: User, reason: str) -> bool:
    """Ban ``user``, disabling sign-in and dropping any live session.

    Sets the ban metadata and flips ``is_active`` off. Idempotent: returns
    ``False`` without touching the row when the account is already banned, so
    the caller can skip emitting a second audit entry.
    """
    if user.banned_at is not None:
        return False
    user.banned_at = timezone.now()
    user.banned_by = by
    user.ban_reason = reason
    user.is_active = False
    user.save(update_fields=["banned_at", "banned_by", "ban_reason", "is_active"])
    return True


def unban_user(user: User, *, by: User) -> str | None:
    """Lift a ban, restoring sign-in and notifications.

    Clears the ban metadata and re-enables ``is_active``. Returns the previous
    ban reason on a real change (for the unban audit trail), or ``None`` when
    the account was not banned (no-op). ``by`` is accepted for symmetry and to
    let the caller attribute the action; the lift itself is attributed via the
    audit entry the view records.
    """
    if user.banned_at is None:
        return None
    previous_reason = user.ban_reason
    user.banned_at = None
    user.banned_by = None
    user.ban_reason = ""
    user.is_active = True
    user.save(update_fields=["banned_at", "banned_by", "ban_reason", "is_active"])
    return previous_reason
