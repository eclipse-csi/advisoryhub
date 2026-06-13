"""Helpers for recording audit log entries.

Always go through :func:`record` (or :func:`record_from_request`) so the
audit log keeps a consistent shape and so secrets are never written into
the metadata JSON by accident.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from django.http import HttpRequest

from common.net import client_ip
from common.users import actor_or_none

from .models import EPHEMERAL_ACTIONS, AccessLogEntry, Action, AuditLogEntry

# Patterns where the credential is preceded by a recognisable prefix; the
# prefix is captured in group(1) and reinstated alongside "***" so the
# redacted line still tells you *what* was hidden.
_TOKEN_PATTERNS = [
    re.compile(r"(https?://)([^/@\s:]+):([^@\s]+)@"),  # https://user:token@host
    re.compile(r"(token=)([^&\s]+)", re.IGNORECASE),
    re.compile(r"(authorization:\s*bearer\s+)([^\s]+)", re.IGNORECASE),
    # JSON private-key fields (App private keys, OIDC keys, etc.). Match
    # only the value so the surrounding JSON keeps its shape.
    re.compile(r'("private_?key"\s*:\s*")([^"]+)(")', re.IGNORECASE),
]

# Patterns where the *whole* match is the secret — there's no useful
# prefix to keep, so the entire match is replaced with "***".
_OPAQUE_SECRET_PATTERNS = [
    # PEM-encoded private keys (RSA, EC, PKCS#8, …). The header/footer
    # alone is enough to identify a key in any error string; we drop the
    # entire block to make sure no body bytes ever reach the audit table.
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    # GitHub-issued tokens: personal access (ghp_), OAuth user-to-server
    # (gho_/ghu_), App installation (ghs_), refresh (ghr_). All share the
    # `gh*_<chars>` shape.
    re.compile(r"\bgh[opusr]_[A-Za-z0-9_]{20,}"),
    # JWT-shaped tokens: header.payload.signature, each segment is
    # base64url. The "eyJ" anchor catches the standard JSON header.
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
]


def redact_secrets(value: Any) -> Any:
    """Strip credentials from strings before they hit the audit log."""
    if value is None:
        return None
    if isinstance(value, str):
        out = value
        for pat in _OPAQUE_SECRET_PATTERNS:
            out = pat.sub("***", out)
        for pat in _TOKEN_PATTERNS:
            out = pat.sub(lambda m: m.group(1) + "***", out)
        return out
    if isinstance(value, dict):
        return {k: redact_secrets(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_secrets(v) for v in value]
    return value


def record(
    *,
    action: str,
    actor=None,
    advisory=None,
    comment=None,
    previous_value: Any = None,
    new_value: Any = None,
    metadata: dict | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditLogEntry | AccessLogEntry:
    """Insert an audit entry and return it.

    Routes the actions in :data:`audit.models.EPHEMERAL_ACTIONS` (advisory
    views + GHSA/PMI machine chatter) to the retention-managed, monthly
    partitioned :class:`~audit.models.AccessLogEntry`; every other action goes
    to the durable, append-only :class:`~audit.models.AuditLogEntry` ledger.
    Secrets are redacted on both paths (INV-AUDIT-2). The signature is
    unchanged so the ~60 call sites need no edits.
    """
    if action not in Action.values:
        raise ValueError(f"Unknown audit action: {action!r}")

    if action in EPHEMERAL_ACTIONS:
        # AccessLogEntry has no previous/new diff or comment columns. The
        # ephemeral actions never carry a diff, but fold any caller-supplied
        # values into metadata under reserved keys so nothing is silently lost.
        meta = dict(metadata or {})
        if previous_value is not None:
            meta.setdefault("_previous_value", previous_value)
        if new_value is not None:
            meta.setdefault("_new_value", new_value)
        return AccessLogEntry.objects.create(
            actor=actor_or_none(actor),
            action=action,
            advisory=advisory,
            metadata=redact_secrets(meta),
            ip_address=ip_address,
            user_agent=(user_agent or "")[:512],
        )

    return AuditLogEntry.objects.create(
        actor=actor_or_none(actor),
        action=action,
        advisory=advisory,
        comment_id=getattr(comment, "pk", None),
        previous_value=redact_secrets(previous_value),
        new_value=redact_secrets(new_value),
        metadata=redact_secrets(metadata or {}),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:512],
    )


def record_from_request(request: HttpRequest, **kwargs) -> AuditLogEntry | AccessLogEntry:
    kwargs.setdefault("actor", getattr(request, "user", None))
    kwargs.setdefault("ip_address", client_ip(request))
    kwargs.setdefault("user_agent", request.META.get("HTTP_USER_AGENT", ""))
    return record(**kwargs)


def pruned_history_floor() -> datetime | None:
    """Most aggressive retention boundary ever applied by ``prune_audit``, or None.

    Returns the **maximum** ``cutoff`` across all surviving ``AUDIT_PRUNED``
    entries — audit events before this instant may have been removed from the
    ledger (see :func:`audit.retention.prune_audit_older_than`). The most recent
    prune by timestamp is *not* necessarily the most aggressive (a later sweep
    may use a smaller/earlier horizon), so we max over the recorded cutoffs
    rather than reading the latest row. The max-cutoff entry itself can never be
    pruned: its ``created_at`` is stamped after its own delete and so postdates
    its cutoff, which is at least as late as any later sweep's cutoff.

    Cheap and uncached: ``action`` is indexed and ``AUDIT_PRUNED`` rows are few
    (one per sweep). Returns ``None`` when no prune has ever run.
    """
    best: datetime | None = None
    for meta in AuditLogEntry.objects.filter(action=Action.AUDIT_PRUNED).values_list(
        "metadata", flat=True
    ):
        raw = (meta or {}).get("cutoff")
        if not raw:
            continue
        try:
            dt = datetime.fromisoformat(raw)
        except (TypeError, ValueError):
            continue
        if best is None or dt > best:
            best = dt
    return best
