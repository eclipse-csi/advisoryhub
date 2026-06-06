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

from accounts.utils import mask_email

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

    return {"user": user, "fallback": fallback, "name": name, "reveal": reveal}
