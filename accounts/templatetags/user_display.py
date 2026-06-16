"""Template tags for rendering users consistently across the UI.

Use ``{% user_chip user %}`` everywhere a user is mentioned. The chip shows the
display name; a hover/focus popover reveals the email and group memberships —
but only for **owners** of the advisory in scope (``viewer_can_see_emails`` in
the context) and for a user looking at their *own* chip. Everyone else sees
names only, because another participant's email is PII they don't need (see
``advisories.permissions.can_see_user_emails`` / ``INV-PRIVACY-4``).
"""

from __future__ import annotations

from django import template
from django.conf import settings

from accounts.utils import mask_email
from common.constants import SECURITY_TEAM_DISPLAY_NAME

register = template.Library()


@register.inclusion_tag("accounts/_user_chip.html", takes_context=True)
def user_chip(context, user, fallback: str = "—"):
    """Render a user as a name chip, with an email + groups popover for owners.

    ``user`` may be ``None`` (e.g. a deleted account, or a "system" audit
    actor); in that case the ``fallback`` string is rendered with no popover.

    Email visibility is decided server-side and merely *displayed* here
    (``INV-AUTH-1``): the popover — and the email-as-name fallback — appear only
    when the context flag ``viewer_can_see_emails`` is set (owners + global
    admins, set by the view / context processor), or when the chip is the
    viewer's own account. Otherwise the name falls back to a masked email.
    """
    reveal = bool(context.get("viewer_can_see_emails", False))
    if not reveal and user is not None:
        # A user always sees their own email, regardless of role.
        viewer = getattr(context.get("request"), "user", None)
        if viewer is not None and getattr(viewer, "is_authenticated", False):
            reveal = viewer.pk == user.pk

    if user is None:
        name = fallback
    elif reveal:
        name = (user.display_name or "").strip() or user.email or fallback
    else:
        name = (user.display_name or "").strip() or mask_email(user.email) or fallback

    # Mark global security-team / admin members so they're identifiable wherever
    # they're named. Iterate the already-loaded ``groups.all()`` rather than the
    # ``User.is_global_admin`` property (a separate ``.exists()`` query): this
    # reuses the prefetch cache and the same fetch the popover performs, so admin
    # chips add no extra queries when callers prefetch ``groups`` (INV-AUTH-1 —
    # display only; authorization stays server-side).
    is_security_team = user is not None and any(
        g.name == settings.OIDC_ADMIN_GROUP for g in user.groups.all()
    )

    return {
        "user": user,
        "fallback": fallback,
        "name": name,
        "reveal": reveal,
        "is_security_team": is_security_team,
        # Inclusion tags don't receive context processors, so feed the friendly
        # name + admin-group slug from the same source the rest of the UI uses.
        "security_team_label": SECURITY_TEAM_DISPLAY_NAME,
        "admin_group_name": settings.OIDC_ADMIN_GROUP,
    }
