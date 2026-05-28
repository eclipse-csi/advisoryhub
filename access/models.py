"""Per-advisory access grants and pending invitations.

A grant records an explicit permission for either a User or a Group on a
specific Advisory. The permission resolution layer (advisories.permissions)
combines these with project-team membership and global admin rules.

Pending invitations let a user grant access by email to someone who has not
yet logged in. On their first OIDC login, ``redeem_invitations_for_user``
turns matching invitations into real grants. Email matching is case-
insensitive but otherwise strict — a different email cannot redeem.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


class Permission(models.TextChoices):
    VIEWER = "viewer", "Viewer"
    COLLABORATOR = "collaborator", "Collaborator"

    # The `owner` role is intentionally NOT a choice here. Owner derives from
    # project security team membership (or global admin) and is never granted
    # via this table — keeping it out of `choices` makes "owner row in the DB"
    # structurally impossible.


class PrincipalType(models.TextChoices):
    USER = "user", "User"
    GROUP = "group", "Group"


class AdvisoryAccessGrant(models.Model):
    """Explicit per-advisory grant for either a User or a Group."""

    advisory = models.ForeignKey(
        "advisories.Advisory", on_delete=models.CASCADE, related_name="access_grants"
    )
    principal_type = models.CharField(max_length=8, choices=PrincipalType.choices)
    principal_id = models.BigIntegerField()
    permission = models.CharField(max_length=16, choices=Permission.choices)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )

    class Meta:
        unique_together = [("advisory", "principal_type", "principal_id")]
        indexes = [
            models.Index(fields=["principal_type", "principal_id"]),
            models.Index(fields=["advisory", "permission"]),
        ]

    def __str__(self) -> str:
        return f"{self.principal_type}:{self.principal_id} {self.permission} on {self.advisory_id}"

    def principal(self):
        """Return the actual User or Group instance, or None if missing."""
        if self.principal_type == PrincipalType.USER:
            from accounts.models import User

            return User.objects.filter(pk=self.principal_id).first()
        from django.contrib.auth.models import Group

        return Group.objects.filter(pk=self.principal_id).first()


def _make_token() -> str:
    return secrets.token_urlsafe(32)


def _default_invitation_expiry():
    return timezone.now() + timedelta(days=14)


class PendingInvitation(models.Model):
    """An access grant pending the recipient's first authenticated login.

    The grant is *not* attached until ``redeem_invitations_for_user`` matches
    the recipient's authenticated email. Email match is case-insensitive.
    """

    advisory = models.ForeignKey(
        "advisories.Advisory", on_delete=models.CASCADE, related_name="pending_invitations"
    )
    email = models.EmailField()
    permission = models.CharField(max_length=16, choices=Permission.choices)
    token = models.CharField(max_length=64, unique=True, default=_make_token)
    expires_at = models.DateTimeField(default=_default_invitation_expiry)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    redeemed_at = models.DateTimeField(null=True, blank=True)
    redeemed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )

    class Meta:
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["advisory", "redeemed_at"]),
        ]

    def __str__(self) -> str:
        return f"invite {self.email} -> {self.advisory_id} ({self.permission})"

    def clean(self):
        super().clean()
        if not self.email:
            raise ValidationError({"email": "Required."})

    def is_expired(self, *, now=None) -> bool:
        return (now or timezone.now()) >= self.expires_at

    def is_pending(self, *, now=None) -> bool:
        return self.redeemed_at is None and not self.is_expired(now=now)
