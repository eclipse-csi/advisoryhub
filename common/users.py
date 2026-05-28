"""User/actor helpers shared across apps."""

from __future__ import annotations


def actor_or_none(user):
    """Return ``user`` when it is an authenticated user, else ``None``.

    Normalises ``AnonymousUser`` / ``None`` / system callers to ``None`` so
    audit rows and workflow foreign keys store a real actor or nothing —
    never a sentinel anonymous user.
    """
    return user if (user and getattr(user, "is_authenticated", False)) else None
