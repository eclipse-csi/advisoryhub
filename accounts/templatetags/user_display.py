"""Template tags for rendering users consistently across the UI.

Use ``{% user_chip user %}`` everywhere a user is mentioned so the UI shows
the display name with a hover/focus popover revealing the email and the
user's group memberships.
"""

from __future__ import annotations

from django import template

register = template.Library()


@register.inclusion_tag("accounts/_user_chip.html")
def user_chip(user, fallback: str = "—"):
    """Render a user as a name chip with an email + groups popover on hover.

    ``user`` may be ``None`` (e.g. a deleted account, or a "system" audit
    actor); in that case the ``fallback`` string is rendered with no popover.
    """
    return {"user": user, "fallback": fallback}
