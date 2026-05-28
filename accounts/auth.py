"""OIDC authentication backend.

Maps OIDC claims to AdvisoryHub users and rebuilds Django group membership
from the configured group claim on every login. The DB ``groups`` mirror is
considered cache-only — never trusted from form data.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.models import Group
from django.http import HttpRequest
from django.shortcuts import resolve_url
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import absolutify

from .models import User

log = logging.getLogger(__name__)


def _email_is_verified(claims: dict[str, Any]) -> bool:
    """Whether the OIDC ``email`` claim may be trusted for account linking.

    Defaults to ``True`` when the OP omits ``email_verified`` (e.g. Kanidm,
    our single trusted IdP), so account-linking-by-email keeps working. Only
    an *explicit* falsey value blocks the link — closing the takeover vector
    where, in a multi-IdP or unverified-email setup, an attacker could
    register a victim's email and inherit their existing account. The stable
    ``sub`` match is unaffected; this only gates the email *fallback*.
    """
    verified = claims.get("email_verified", True)
    if isinstance(verified, str):
        return verified.strip().lower() in ("true", "1", "yes")
    return bool(verified)


class AdvisoryHubOIDCBackend(OIDCAuthenticationBackend):
    """OIDC backend that syncs group membership from a configurable claim."""

    def filter_users_by_claims(self, claims: dict[str, Any]):
        sub = claims.get("sub")
        if sub:
            users = self.UserModel.objects.filter(oidc_subject=sub)
            if users.exists():
                return users
        email = claims.get("email")
        if email and _email_is_verified(claims):
            return self.UserModel.objects.filter(email__iexact=email)
        return self.UserModel.objects.none()

    def create_user(self, claims: dict[str, Any]) -> User:
        email = claims.get("email")
        user = User.objects.create_user(email=email)
        self._apply_claims(user, claims)
        self._post_login_hooks(user, claims)
        return user

    def update_user(self, user: User, claims: dict[str, Any]) -> User:
        self._apply_claims(user, claims)
        self._post_login_hooks(user, claims)
        return user

    # --- internals -----------------------------------------------------------

    def _apply_claims(self, user: User, claims: dict[str, Any]) -> None:
        user.oidc_subject = claims.get("sub", "") or user.oidc_subject
        user.display_name = claims.get("name") or user.display_name
        user.first_name = claims.get("given_name", "") or user.first_name
        user.last_name = claims.get("family_name", "") or user.last_name
        if not user.email and claims.get("email"):
            user.email = claims["email"]
        user.save()
        sync_groups_from_claims(user, claims)
        # OIDC admin group is the source of truth for Django admin access.
        # Re-evaluate on every login so a demotion in the IdP cleanly revokes
        # /admin/, matching the one-way group-sync rule in CLAUDE.md.
        desired = user.is_global_admin
        if user.is_staff != desired or user.is_superuser != desired:
            user.is_staff = desired
            user.is_superuser = desired
            user.save(update_fields=["is_staff", "is_superuser"])

    def _post_login_hooks(self, user: User, claims: dict[str, Any]) -> None:
        # Redeem any pending invitations addressed to this user's email.
        from access.services import redeem_invitations_for_user

        redeem_invitations_for_user(user)


def sync_groups_from_claims(user: User, claims: dict[str, Any]) -> None:
    """Replace ``user.groups`` with groups listed in the configured claim.

    The set is fully replaced on every login, so a removed claim cleanly
    drops the membership. Unknown groups are auto-created.

    Two Kanidm-driven filters keep noise out of Django's ``auth_group``:

    * **Require SPN form** (``name@domain``). Kanidm emits each group twice
      — once by UUID and once by SPN — so without this we'd end up with
      duplicate ``Group`` rows named like
      ``65767ecb-6ad3-480f-9b2b-ab9fe51c2378``. Stripping the SPN suffix
      yields the bare name that the rest of the codebase compares against
      (e.g. ``OIDC_ADMIN_GROUP`` is configured as ``advisoryhub-security``).
    * **Drop the ``idm_*`` prefix** after stripping. These are Kanidm's
      internal IDM groups (``idm_all_persons``, ``idm_all_accounts``,
      ``idm_people_self_name_write``) which leak into the claim but are
      meaningless to AdvisoryHub.

    OPs other than Kanidm must therefore also emit groups in SPN form to be
    picked up. If we ever wire a new IdP that emits bare-name groups, this
    function needs revisiting.
    """
    claim_name = settings.OIDC_GROUP_CLAIM
    claimed = claims.get(claim_name) or []
    if isinstance(claimed, str):
        claimed = [claimed]
    if not isinstance(claimed, (list, tuple, set)):
        log.warning("OIDC group claim %r has unexpected type %s", claim_name, type(claimed))
        claimed = []

    desired_names: set[str] = set()
    for name in claimed:
        if not name:
            continue
        text = str(name).strip()
        if "@" not in text:
            continue  # drop UUIDs and other non-SPN entries
        bare = text.split("@", 1)[0]
        if not bare or bare.startswith("idm_"):
            continue  # drop Kanidm internal IDM machinery
        desired_names.add(bare)

    groups: list[Group] = []
    for name in desired_names:
        group, _ = Group.objects.get_or_create(name=name)
        groups.append(group)
    user.groups.set(groups)


def provider_logout(request: HttpRequest) -> str:
    """Build an RP-initiated logout URL for the configured OIDC OP.

    Wired in via ``OIDC_OP_LOGOUT_URL_METHOD`` so mozilla-django-oidc's
    :class:`OIDCLogoutView` redirects the browser to the OP's
    ``end_session_endpoint`` after clearing the local Django session. Without
    this the OP-side SSO session survives, so the next protected page silently
    re-authenticates the user and "Sign out" appears to do nothing.

    Returns the OP end-session URL with ``id_token_hint`` and
    ``post_logout_redirect_uri`` parameters. Falls back to
    ``LOGOUT_REDIRECT_URL`` when the OP logout endpoint isn't configured.
    """
    end_session = getattr(settings, "OIDC_OP_LOGOUT_ENDPOINT", "")
    logout_redirect = resolve_url(getattr(settings, "LOGOUT_REDIRECT_URL", "/"))
    if not end_session:
        return logout_redirect

    params: dict[str, str] = {
        "post_logout_redirect_uri": absolutify(request, logout_redirect),
    }
    id_token = request.session.get("oidc_id_token")
    if id_token:
        params["id_token_hint"] = id_token
    return f"{end_session}?{urlencode(params)}"
