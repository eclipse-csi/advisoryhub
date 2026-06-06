"""User-identity display helpers."""

from __future__ import annotations


def mask_email(value: str | None) -> str:
    """Mask an email to its first character + domain.

    ``"alice@example.org"`` becomes ``"a•••@example.org"`` — enough to hint at
    identity without exposing the full address. Used to redact other users'
    emails from viewers who aren't owners of an advisory.

    Non-email strings (no ``@`` — e.g. a group name) and empty values are
    returned unchanged, so any principal label can be funnelled through this
    safely.
    """
    if not value or "@" not in value:
        return value or ""
    local, _, domain = value.partition("@")
    return f"{local[:1]}•••@{domain}"
