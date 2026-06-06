"""Per-advisory timeline of audit events.

The advisory detail page renders a unified timeline that intermingles
comments with audit events (à la GitHub PR timeline). This module owns:

* The visibility policy — which audit actions appear in the timeline, and
  for which roles. Filtering runs at the DB layer (matching the
  comments-list pattern) so a template change cannot accidentally surface
  a hidden row.
* The action → human-readable summary mapping used by ``_event.html``.

Comments are merged into the timeline by
``comments.services.advisory_timeline``; the comment row itself is what
gets rendered, not its ``comment.created`` audit entry.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from accounts.utils import mask_email
from audit.models import Action, AuditLogEntry

from . import permissions as perms
from .models import Advisory

# ---------------------------------------------------------------------------
# Visibility tiers
# ---------------------------------------------------------------------------

_TIER_A_ACTIONS: frozenset[str] = frozenset(
    {
        Action.ADVISORY_CREATED,
        Action.ADVISORY_TRIAGE_PROMOTED,
        Action.ADVISORY_STATE_CHANGED,
        Action.ADVISORY_PUBLISHED,
        Action.ADVISORY_DISMISSED,
        Action.ADVISORY_PROJECT_CHANGED,
        Action.ADVISORY_SUBMITTED_FOR_REVIEW,
        Action.ADVISORY_REVIEW_APPROVED,
        Action.ADVISORY_REVIEW_CHANGES_REQUESTED,
        Action.ADVISORY_REVIEW_WITHDRAWN,
        Action.ADVISORY_REVIEW_APPROVAL_INVALIDATED,
        Action.ADVISORY_REVIEW_APPROVAL_REVOKED,
        Action.CVE_REQUESTED,
        Action.CVE_TASK_STATUS_CHANGED,
        Action.CVE_MARKED_REJECTED_AT_CVE_ORG,
    }
)

_TIER_B_ACTIONS: frozenset[str] = frozenset(
    {
        Action.ACCESS_GRANTED,
        Action.ACCESS_REVOKED,
        Action.INVITATION_CREATED,
        Action.INVITATION_REDEEMED,
        Action.INVITATION_REVOKED,
        Action.ADVISORY_EDITED,
        Action.CVE_REQUEST_BANNED,
        Action.CVE_REQUEST_CANCELLED,
        Action.CVE_UNASSIGNED,
        Action.PUBLICATION_EXPORT_STARTED,
        Action.PUBLICATION_EXPORT_COMPLETED,
        Action.PUBLICATION_EXPORT_FAILED,
        Action.PUBLICATION_GIT_PUSH,
        Action.PUBLICATION_GIT_PUSH_FAILED,
        Action.REVIEW_TASK_STATUS_CHANGED,
    }
)

_TIER_C_ACTIONS: frozenset[str] = frozenset(
    {
        Action.ADVISORY_TRIAGE_SUBMITTED,
        Action.ADVISORY_FLAGGED_FOR_ROUTING,
        Action.ADVISORY_ROUTING_FLAG_CLEARED,
        Action.ADVISORY_ACCESS_REVIEW_DISMISSED,
        Action.GHSA_LINKED_ADVISORY_CREATED,
        Action.GHSA_CVE_PUSH_REQUESTED,
        Action.GHSA_CVE_PUSH_SUCCEEDED,
        Action.GHSA_CVE_PUSH_FAILED,
        Action.GHSA_CVE_CONFLICT_DETECTED,
    }
)

TIMELINE_ACTIONS_BY_TIER: dict[str, frozenset[str]] = {
    "viewer": _TIER_A_ACTIONS,
    "collaborator": _TIER_A_ACTIONS | _TIER_B_ACTIONS,
    "admin_owner": _TIER_A_ACTIONS | _TIER_B_ACTIONS | _TIER_C_ACTIONS,
}

# Excluded actions are documented in MEMORY/the plan; they are filtered out
# by virtue of being absent from every tier above.
EXCLUDED_ACTIONS: frozenset[str] = frozenset(Action.values) - (
    _TIER_A_ACTIONS | _TIER_B_ACTIONS | _TIER_C_ACTIONS
)


def visible_actions(user, advisory: Advisory) -> frozenset[str]:
    """Return the audit actions ``user`` may see on this advisory's timeline."""
    perm = perms.resolved_permission(user, advisory)
    if perm is None:
        return frozenset()
    # Owners and global admins get the full tier-C view. resolved_permission
    # already returns ``"owner"`` for admins, so the explicit admin check is
    # belt-and-braces against future changes to the resolution order.
    if perm == "owner" or perms.is_global_admin(user):
        return TIMELINE_ACTIONS_BY_TIER["admin_owner"]
    if perm == "collaborator":
        return TIMELINE_ACTIONS_BY_TIER["collaborator"]
    return TIMELINE_ACTIONS_BY_TIER["viewer"]


def events_for_advisory(advisory: Advisory, *, viewer) -> Iterable[AuditLogEntry]:
    """Timeline-eligible audit events ``viewer`` may see on ``advisory``."""
    allowed = visible_actions(viewer, advisory)
    if not allowed:
        return AuditLogEntry.objects.none()
    return (
        AuditLogEntry.objects.filter(advisory=advisory, action__in=allowed)
        .select_related("actor")
        .prefetch_related("actor__groups")
        .order_by("created_at")
    )


# ---------------------------------------------------------------------------
# Principal label resolution (for access events)
# ---------------------------------------------------------------------------

PrincipalLabels = dict[tuple[str, int], str]


@dataclass(frozen=True)
class PrincipalInfo:
    """Rich principal record for an access event's target.

    ``label`` is the same string ``resolve_principal_labels`` would have
    returned (display_name → email → "unknown user" for users, ``name``
    for groups), so callers that only need prose keep working. ``user``
    or ``group`` is the live ORM object — used by the timeline to render
    a chip with email + groups on hover for user principals.
    """

    kind: str  # "user" | "group"
    pk: int
    label: str
    user: object | None = None  # accounts.models.User when kind == "user"
    group: object | None = None  # django.contrib.auth.Group when kind == "group"


Principals = dict[tuple[str, int], PrincipalInfo]


@dataclass(frozen=True)
class SummaryChunk:
    """One renderable piece of an audit-event summary.

    Pure-text chunks have ``user`` and ``group`` both ``None``.
    Principal chunks set exactly one of them; the template renders user
    chunks via ``{% user_chip %}`` and group chunks as styled prose.

    A deleted/unresolvable principal degrades to a pure-text chunk whose
    ``text`` reads "a user" / "a group" — no chip, no broken popover.
    """

    text: str
    user: object | None = None
    group: object | None = None


def _principal_key(value: Any) -> tuple[str, int] | None:
    d = _as_dict(value)
    ptype = d.get("principal_type")
    pid = d.get("principal_id")
    if isinstance(ptype, str) and isinstance(pid, int):
        return (ptype, pid)
    return None


def resolve_principals(entries: Iterable[AuditLogEntry]) -> Principals:
    """Bulk-resolve ``(principal_type, principal_id) -> PrincipalInfo`` for access events.

    Two DB queries — one against ``accounts.User`` (for user principals)
    and one against ``django.contrib.auth.models.Group`` — regardless of
    how many access events appear on the advisory. The User query also
    prefetches ``groups`` so each user chip's hover popover doesn't
    trigger a per-row query. Deleted principals are simply absent from
    the result; formatters fall back to a generic phrase.
    """
    user_ids: set[int] = set()
    group_ids: set[int] = set()
    for entry in entries:
        if entry.action == Action.ACCESS_GRANTED:
            key = _principal_key(entry.new_value)
        elif entry.action == Action.ACCESS_REVOKED:
            key = _principal_key(entry.previous_value)
        else:
            continue
        if key is None:
            continue
        ptype, pid = key
        if ptype == "user":
            user_ids.add(pid)
        elif ptype == "group":
            group_ids.add(pid)

    out: Principals = {}
    if user_ids:
        from accounts.models import User

        for u in User.objects.filter(pk__in=user_ids).prefetch_related("groups"):
            out[("user", u.pk)] = PrincipalInfo(
                kind="user",
                pk=u.pk,
                label=u.display_label(fallback="unknown user"),
                user=u,
            )
    if group_ids:
        from django.contrib.auth.models import Group

        for g in Group.objects.filter(pk__in=group_ids):
            out[("group", g.pk)] = PrincipalInfo(
                kind="group",
                pk=g.pk,
                label=g.name,
                group=g,
            )
    return out


def resolve_principal_labels(entries: Iterable[AuditLogEntry]) -> PrincipalLabels:
    """Bulk-resolve ``(principal_type, principal_id) -> label`` for access events.

    Two DB queries — one against ``accounts.User`` (for user principals)
    and one against ``django.contrib.auth.models.Group`` — regardless of
    how many access events appear on the advisory. Deleted principals
    are simply absent from the result; formatters fall back to a generic
    phrase.

    This is a lean variant of :func:`resolve_principals` that skips the
    ``groups`` prefetch — callers that only need prose labels (logs,
    JSON serialisers, the non-chip code paths) don't pay for it.
    """
    user_ids: set[int] = set()
    group_ids: set[int] = set()
    for entry in entries:
        if entry.action == Action.ACCESS_GRANTED:
            key = _principal_key(entry.new_value)
        elif entry.action == Action.ACCESS_REVOKED:
            key = _principal_key(entry.previous_value)
        else:
            continue
        if key is None:
            continue
        ptype, pid = key
        if ptype == "user":
            user_ids.add(pid)
        elif ptype == "group":
            group_ids.add(pid)

    labels: PrincipalLabels = {}
    if user_ids:
        from accounts.models import User

        for u in User.objects.filter(pk__in=user_ids):
            labels[("user", u.pk)] = u.display_label(fallback="unknown user")
    if group_ids:
        from django.contrib.auth.models import Group

        for g in Group.objects.filter(pk__in=group_ids):
            labels[("group", g.pk)] = g.name
    return labels


# ---------------------------------------------------------------------------
# Human-readable summaries
# ---------------------------------------------------------------------------

Formatter = Callable[[AuditLogEntry, PrincipalLabels], str]
_FORMATTERS: dict[str, Formatter] = {}

# Chunk formatters are a parallel registry populated only for actions
# whose prose embeds a principal name we want to render as a chip
# (ACCESS_GRANTED / ACCESS_REVOKED today). Every other action degrades
# to ``[SummaryChunk(text=summary_for(...))]`` via :func:`summary_chunks_for`.
ChunksFormatter = Callable[[AuditLogEntry, Principals], list[SummaryChunk]]
ChunksCoalescer = Callable[[list[AuditLogEntry], Principals], list[SummaryChunk]]
_CHUNK_FORMATTERS: dict[str, ChunksFormatter] = {}
_CHUNK_COALESCERS: dict[str, ChunksCoalescer] = {}


def _register(action: str) -> Callable[[Formatter], Formatter]:
    def deco(fn: Formatter) -> Formatter:
        _FORMATTERS[action] = fn
        return fn

    return deco


def _register_chunks(action: str) -> Callable[[ChunksFormatter], ChunksFormatter]:
    def deco(fn: ChunksFormatter) -> ChunksFormatter:
        _CHUNK_FORMATTERS[action] = fn
        return fn

    return deco


def _register_chunks_coalescer(
    action: str,
) -> Callable[[ChunksCoalescer], ChunksCoalescer]:
    def deco(fn: ChunksCoalescer) -> ChunksCoalescer:
        _CHUNK_COALESCERS[action] = fn
        return fn

    return deco


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _state_of(value: Any) -> str:
    return str(_as_dict(value).get("state", "?"))


def _project_of(value: Any) -> str:
    # ADVISORY_PROJECT_CHANGED is emitted with either a slug string or a
    # ``{"project_slug": ...}`` dict depending on the call site.
    if isinstance(value, str):
        return value
    return str(_as_dict(value).get("project_slug") or _as_dict(value).get("project") or "?")


# Human-readable labels for ``Advisory.to_payload()`` keys, used by the
# ``advisory.edited`` formatter and coalescer to render which payload
# fields actually moved. Unknown keys fall through to the raw key so a
# future addition to ``to_payload`` degrades to "edited the advisory's
# foo_bar" instead of vanishing.
_PAYLOAD_FIELD_LABELS: dict[str, str] = {
    "summary": "summary",
    "details": "description",
    "aliases": "aliases",
    "references": "references",
    "affected": "affected packages",
    "severity": "severity",
    "cwe_ids": "CWE list",
    "credits": "credits",
    "withdrawn_reason": "withdrawn reason",
    "kind": "advisory kind",
    "ghsa_id": "GHSA id",
    "ghsa_owner": "GHSA owner",
    "ghsa_repo": "GHSA repo",
    "ghsa_metadata_synced_at": "GHSA sync timestamp",
    "advisory_id": "advisory id",
    "project_slug": "project",
    "assigned_cve_id": "assigned CVE id",
}


def _humanize_field(key: str) -> str:
    return _PAYLOAD_FIELD_LABELS.get(key, key)


def _format_field_list(keys: list[str]) -> str:
    """English-joined list of payload-field labels. No truncation — the
    universe is the ~17 keys in :data:`_PAYLOAD_FIELD_LABELS`.
    """
    labels = [_humanize_field(k) for k in keys]
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]}"
    return ", ".join(labels[:-1]) + ", and " + labels[-1]


@_register(Action.ADVISORY_CREATED)
def _f_created(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "created this advisory"


@_register(Action.ADVISORY_TRIAGE_PROMOTED)
def _f_triage_promoted(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "promoted this report from triage to draft"


@_register(Action.ADVISORY_STATE_CHANGED)
def _f_state_changed(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    prev = _as_dict(e.previous_value)
    new = _as_dict(e.new_value)
    if "state" in prev or "state" in new:
        return f"changed state from {prev.get('state', '?')} to {new.get('state', '?')}"
    if "review_status" in prev or "review_status" in new:
        return (
            f"changed review status from {prev.get('review_status', '?')} "
            f"to {new.get('review_status', '?')}"
        )
    return "changed state"


@_register(Action.ADVISORY_PUBLISHED)
def _f_published(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "published this advisory"


@_register(Action.ADVISORY_DISMISSED)
def _f_dismissed(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    reason = _as_dict(e.metadata).get("reason")
    if reason:
        return f"dismissed this advisory: {reason}"
    return "dismissed this advisory"


@_register(Action.ADVISORY_PROJECT_CHANGED)
def _f_project_changed(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return f"moved this advisory from {_project_of(e.previous_value)} to {_project_of(e.new_value)}"


@_register(Action.ADVISORY_EDITED)
def _f_edited(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    version = _as_dict(e.new_value).get("version") or _as_dict(e.metadata).get("version")
    changed = _as_dict(e.metadata).get("changed_fields") or []
    if isinstance(changed, list) and changed:
        fields_text = _format_field_list(list(changed))
        if version:
            return f"edited the advisory's {fields_text} (version {version})"
        return f"edited the advisory's {fields_text}"
    if version:
        return f"edited the advisory (version {version})"
    return "edited the advisory"


@_register(Action.ADVISORY_SUBMITTED_FOR_REVIEW)
def _f_submitted(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "submitted this advisory for review"


@_register(Action.ADVISORY_REVIEW_APPROVED)
def _f_approved(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "approved the review"


@_register(Action.ADVISORY_REVIEW_CHANGES_REQUESTED)
def _f_changes_requested(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "requested changes to the advisory"


@_register(Action.ADVISORY_REVIEW_WITHDRAWN)
def _f_withdrew(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "withdrew the review submission"


@_register(Action.ADVISORY_REVIEW_APPROVAL_INVALIDATED)
def _f_invalidated(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "invalidated the prior approval by editing the advisory"


@_register(Action.ADVISORY_REVIEW_APPROVAL_REVOKED)
def _f_revoked_approval(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "revoked the prior approval"


@_register(Action.ACCESS_GRANTED)
def _f_access_granted(e: AuditLogEntry, labels: PrincipalLabels) -> str:
    nv = _as_dict(e.new_value)
    perm = nv.get("permission", "?")
    key = _principal_key(nv)
    label = labels.get(key) if key else None
    if _as_dict(e.metadata).get("updated"):
        if label:
            return f"updated {label}'s access to {perm}"
        principal = nv.get("principal_type", "principal")
        return f"updated a {principal}'s access to {perm}"
    if label:
        return f"granted {perm} access to {label}"
    principal = nv.get("principal_type", "principal")
    return f"granted {perm} access to a {principal}"


@_register(Action.ACCESS_REVOKED)
def _f_access_revoked(e: AuditLogEntry, labels: PrincipalLabels) -> str:
    pv = _as_dict(e.previous_value)
    perm = pv.get("permission", "?")
    key = _principal_key(pv)
    label = labels.get(key) if key else None
    if label:
        return f"revoked {perm} access from {label}"
    principal = pv.get("principal_type", "principal")
    return f"revoked {perm} access from a {principal}"


def _principal_chunk(payload: dict, principals: Principals) -> SummaryChunk:
    """Build the principal portion of an access-event summary as a chunk.

    Returns a chip-bearing chunk if the principal still exists, or a
    plain-text "a user" / "a group" chunk if it was deleted or the
    payload is malformed.
    """
    key = _principal_key(payload)
    p = principals.get(key) if key else None
    if p is not None:
        return SummaryChunk(text=p.label, user=p.user, group=p.group)
    fallback = payload.get("principal_type", "principal")
    return SummaryChunk(text=f"a {fallback}")


@_register_chunks(Action.ACCESS_GRANTED)
def _cf_access_granted(e: AuditLogEntry, principals: Principals) -> list[SummaryChunk]:
    nv = _as_dict(e.new_value)
    perm = nv.get("permission", "?")
    principal = _principal_chunk(nv, principals)
    if _as_dict(e.metadata).get("updated"):
        return [
            SummaryChunk("updated "),
            principal,
            SummaryChunk(f"'s access to {perm}"),
        ]
    return [SummaryChunk(f"granted {perm} access to "), principal]


@_register_chunks(Action.ACCESS_REVOKED)
def _cf_access_revoked(e: AuditLogEntry, principals: Principals) -> list[SummaryChunk]:
    pv = _as_dict(e.previous_value)
    perm = pv.get("permission", "?")
    principal = _principal_chunk(pv, principals)
    return [SummaryChunk(f"revoked {perm} access from "), principal]


@_register(Action.INVITATION_CREATED)
def _f_invitation_created(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    nv = _as_dict(e.new_value)
    perm = nv.get("permission", "?")
    email = nv.get("email")
    if _as_dict(e.metadata).get("updated"):
        if email:
            return f"updated the pending invitation for {email} to {perm}"
        return f"updated a pending invitation to {perm}"
    if email:
        return f"invited {email} with {perm} access"
    return f"invited someone with {perm} access"


@_register(Action.INVITATION_REDEEMED)
def _f_invitation_redeemed(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    perm = _as_dict(e.new_value).get("permission", "?")
    return f"accepted a {perm} access invitation"


@_register(Action.INVITATION_REVOKED)
def _f_invitation_revoked(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    pv = _as_dict(e.previous_value)
    email = pv.get("email")
    if email:
        return f"revoked the pending invitation for {email}"
    return "revoked a pending invitation"


@_register(Action.CVE_REQUESTED)
def _f_cve_requested(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "requested a CVE for this advisory"


@_register(Action.CVE_TASK_STATUS_CHANGED)
def _f_cve_status(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    pv = _as_dict(e.previous_value).get("status")
    nv = _as_dict(e.new_value).get("status")
    cve_id = _as_dict(e.new_value).get("cve_id")
    suffix = f" ({cve_id})" if cve_id else ""
    if pv and nv:
        return f"CVE request status changed from {pv} to {nv}{suffix}"
    if nv:
        return f"CVE request status set to {nv}{suffix}"
    return "CVE request status changed"


@_register(Action.CVE_REQUEST_BANNED)
def _f_cve_banned(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "banned further CVE requests on this advisory"


@_register(Action.CVE_REQUEST_CANCELLED)
def _f_cve_cancelled(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "cancelled the CVE request"


@_register(Action.CVE_UNASSIGNED)
def _f_cve_unassigned(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "unassigned the CVE from this advisory"


@_register(Action.CVE_MARKED_REJECTED_AT_CVE_ORG)
def _f_cve_rejected(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "marked the CVE as rejected at cve.org"


@_register(Action.REVIEW_TASK_STATUS_CHANGED)
def _f_review_status(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    pv = _as_dict(e.previous_value).get("status")
    nv = _as_dict(e.new_value).get("status")
    if pv and nv:
        return f"review task moved from {pv} to {nv}"
    if nv:
        return f"review task set to {nv}"
    return "review task status changed"


@_register(Action.PUBLICATION_EXPORT_STARTED)
def _f_pub_started(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "started a publication export"


@_register(Action.PUBLICATION_EXPORT_COMPLETED)
def _f_pub_completed(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "completed the publication export"


@_register(Action.PUBLICATION_EXPORT_FAILED)
def _f_pub_failed(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    err = _as_dict(e.metadata).get("error") or _as_dict(e.metadata).get("last_error")
    if err:
        return f"publication export failed: {err}"
    return "publication export failed"


@_register(Action.PUBLICATION_GIT_PUSH)
def _f_git_push(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "pushed advisory artifacts to the publication repo"


@_register(Action.PUBLICATION_GIT_PUSH_FAILED)
def _f_git_push_failed(e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    err = _as_dict(e.metadata).get("error") or _as_dict(e.metadata).get("last_error")
    if err:
        return f"publication push failed: {err}"
    return "publication push failed"


@_register(Action.ADVISORY_TRIAGE_SUBMITTED)
def _f_triage_submitted(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "submitted this report via the public intake form"


@_register(Action.ADVISORY_FLAGGED_FOR_ROUTING)
def _f_flagged(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "flagged this advisory for admin routing"


@_register(Action.ADVISORY_ROUTING_FLAG_CLEARED)
def _f_routing_cleared(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "cleared the admin-routing flag"


@_register(Action.ADVISORY_ACCESS_REVIEW_DISMISSED)
def _f_access_review_dismissed(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "dismissed the access review"


@_register(Action.GHSA_LINKED_ADVISORY_CREATED)
def _f_ghsa_linked(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "created this advisory from a linked GHSA"


@_register(Action.GHSA_CVE_PUSH_REQUESTED)
def _f_ghsa_push_req(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "requested a CVE push to GHSA"


@_register(Action.GHSA_CVE_PUSH_SUCCEEDED)
def _f_ghsa_push_ok(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "pushed the CVE to GHSA"


@_register(Action.GHSA_CVE_PUSH_FAILED)
def _f_ghsa_push_fail(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "failed to push the CVE to GHSA"


@_register(Action.GHSA_CVE_CONFLICT_DETECTED)
def _f_ghsa_conflict(_e: AuditLogEntry, _labels: PrincipalLabels) -> str:
    return "detected a GHSA/CVE metadata conflict"


# ---------------------------------------------------------------------------
# Coalescers — collapse runs of same-actor same-action entries
# ---------------------------------------------------------------------------

Coalescer = Callable[[list[AuditLogEntry], PrincipalLabels], str]
RunExtender = Callable[[AuditLogEntry, AuditLogEntry], bool]

_COALESCERS: dict[str, Coalescer] = {}
_RUN_EXTENDERS: dict[str, RunExtender] = {}


def _register_coalescer(
    action: str, *, extends: RunExtender | None = None
) -> Callable[[Coalescer], Coalescer]:
    def deco(fn: Coalescer) -> Coalescer:
        _COALESCERS[action] = fn
        if extends is not None:
            _RUN_EXTENDERS[action] = extends
        return fn

    return deco


def can_coalesce(action: str) -> bool:
    """Whether ``action`` participates in run-coalescing on the timeline."""
    return action in _COALESCERS


def can_extend_run(prev: AuditLogEntry, nxt: AuditLogEntry) -> bool:
    """Whether ``nxt`` can extend the coalescing run started at ``prev``.

    Caller must already have established ``prev`` is coalescable and that
    no comment / non-coalescable event sits between them. This helper
    enforces same actor + same action + the action's own run predicate
    (e.g. version contiguity for edits, same permission for grants).
    """
    if prev.action != nxt.action:
        return False
    if prev.actor_id != nxt.actor_id:
        return False
    if not can_coalesce(prev.action):
        return False
    extender = _RUN_EXTENDERS.get(prev.action)
    if extender is None:
        return True
    return extender(prev, nxt)


def coalesced_summary(entries: list[AuditLogEntry], labels: PrincipalLabels) -> str:
    """Render the rolled-up summary for a coalescable run.

    Falls back to the single-entry formatter (for the last entry) if the
    coalescer raises or if the run only has one entry — defensive against
    formatter bugs killing the page.
    """
    if not entries:
        return ""
    if len(entries) == 1:
        return summary_for(entries[0], principal_labels=labels)
    fn = _COALESCERS.get(entries[0].action)
    if fn is None:
        return summary_for(entries[-1], principal_labels=labels)
    try:
        return fn(entries, labels)
    except Exception:
        return summary_for(entries[-1], principal_labels=labels)


def coalesced_chunks(entries: list[AuditLogEntry], principals: Principals) -> list[SummaryChunk]:
    """Renderable form of :func:`coalesced_summary`: a list of chunks.

    Mirrors the fallback ladder of :func:`coalesced_summary` so behavior
    stays consistent across the string and chunk pipelines.
    """
    if not entries:
        return []
    if len(entries) == 1:
        return summary_chunks_for(entries[0], principals=principals)
    fn = _CHUNK_COALESCERS.get(entries[0].action)
    if fn is None:
        # No chunk coalescer registered for this action — fall back to
        # the plain-string coalesced summary, wrapped as a single chunk.
        labels = {k: v.label for k, v in principals.items()}
        return [SummaryChunk(text=coalesced_summary(entries, labels))]
    try:
        return fn(entries, principals)
    except Exception:
        return summary_chunks_for(entries[-1], principals=principals)


def _format_label_list(labels: list[str], limit: int = 3) -> str:
    """English-style list with an "and N more" tail past ``limit`` items.

    1 → "alice"; 2 → "alice and bob"; 3 → "alice, bob, and chris";
    4+ → "alice, bob, chris, and N more".
    """
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]}"
    if len(labels) <= limit:
        return ", ".join(labels[:-1]) + ", and " + labels[-1]
    shown = labels[:limit]
    remaining = len(labels) - limit
    return ", ".join(shown) + f", and {remaining} more"


# ---- advisory.edited -------------------------------------------------------


def _edited_version(entry: AuditLogEntry) -> int | None:
    v = _as_dict(entry.new_value).get("version")
    if isinstance(v, int):
        return v
    return None


def _extends_advisory_edited(prev: AuditLogEntry, nxt: AuditLogEntry) -> bool:
    pv = _edited_version(prev)
    nv = _edited_version(nxt)
    # If either side has no version we can't prove contiguity; be safe.
    if pv is None or nv is None:
        return False
    return nv == pv + 1


@_register_coalescer(Action.ADVISORY_EDITED, extends=_extends_advisory_edited)
def _c_advisory_edited(entries: list[AuditLogEntry], _labels: PrincipalLabels) -> str:
    versions = [_edited_version(e) for e in entries]
    first, last = versions[0], versions[-1]
    # Union changed_fields across the run, preserving first-seen order so
    # the rendered list is stable for a given input sequence.
    seen: set[str] = set()
    union: list[str] = []
    for entry in entries:
        for field in _as_dict(entry.metadata).get("changed_fields") or []:
            if isinstance(field, str) and field not in seen:
                seen.add(field)
                union.append(field)

    if first is not None and last is not None:
        span = f"versions {first}–{last}"
    else:
        span = f"{len(entries)} edits"
    if union:
        return f"edited the advisory's {_format_field_list(union)} ({span})"
    return f"edited the advisory ({span})"


# ---- access.granted / access.revoked ---------------------------------------


def _granted_run_key(entry: AuditLogEntry) -> tuple[str, str]:
    nv = _as_dict(entry.new_value)
    return (str(nv.get("permission", "")), str(nv.get("principal_type", "")))


def _revoked_run_key(entry: AuditLogEntry) -> tuple[str, str]:
    pv = _as_dict(entry.previous_value)
    return (str(pv.get("permission", "")), str(pv.get("principal_type", "")))


def _extends_access_granted(prev: AuditLogEntry, nxt: AuditLogEntry) -> bool:
    return _granted_run_key(prev) == _granted_run_key(nxt)


def _extends_access_revoked(prev: AuditLogEntry, nxt: AuditLogEntry) -> bool:
    return _revoked_run_key(prev) == _revoked_run_key(nxt)


def _principal_labels_for(
    entries: list[AuditLogEntry],
    labels: PrincipalLabels,
    *,
    from_field: str,
) -> list[str]:
    out: list[str] = []
    for entry in entries:
        payload = entry.new_value if from_field == "new_value" else entry.previous_value
        key = _principal_key(payload)
        if key is None:
            continue
        label = labels.get(key)
        if label is None:
            # Deleted or unresolvable principal — fall back to the principal_type
            # so the list still reads sensibly ("a user").
            label = f"a {key[0]}"
        out.append(label)
    return out


@_register_coalescer(Action.ACCESS_GRANTED, extends=_extends_access_granted)
def _c_access_granted(entries: list[AuditLogEntry], labels: PrincipalLabels) -> str:
    perm, _principal_type = _granted_run_key(entries[0])
    targets = _principal_labels_for(entries, labels, from_field="new_value")
    return f"granted {perm} access to {_format_label_list(targets)}"


@_register_coalescer(Action.ACCESS_REVOKED, extends=_extends_access_revoked)
def _c_access_revoked(entries: list[AuditLogEntry], labels: PrincipalLabels) -> str:
    perm, _principal_type = _revoked_run_key(entries[0])
    targets = _principal_labels_for(entries, labels, from_field="previous_value")
    return f"revoked {perm} access from {_format_label_list(targets)}"


def _principal_chunks_for(
    entries: list[AuditLogEntry],
    principals: Principals,
    *,
    from_field: str,
) -> list[SummaryChunk]:
    """Build one chip-bearing chunk per entry's principal payload."""
    out: list[SummaryChunk] = []
    for entry in entries:
        payload = _as_dict(entry.new_value if from_field == "new_value" else entry.previous_value)
        out.append(_principal_chunk(payload, principals))
    return out


def _join_principal_chunks(chunks: list[SummaryChunk], *, limit: int = 3) -> list[SummaryChunk]:
    """Render a list of principal chunks as an English-style enumeration.

    Mirrors :func:`_format_label_list` but interleaves text separators
    between the principal chunks so the template can render each chip
    inline. Past ``limit`` items, surplus principals collapse into a
    plain "and N more" text chunk so the row stays compact.
    """
    n = len(chunks)
    if n == 0:
        return []
    if n == 1:
        return [chunks[0]]
    if n == 2:
        return [chunks[0], SummaryChunk(" and "), chunks[1]]
    if n <= limit:
        out: list[SummaryChunk] = []
        for i, c in enumerate(chunks[:-1]):
            out.append(c)
            out.append(SummaryChunk(", " if i < n - 2 else ", and "))
        out.append(chunks[-1])
        return out
    shown = chunks[:limit]
    remaining = n - limit
    out = []
    for i, c in enumerate(shown):
        out.append(c)
        if i < limit - 1:
            out.append(SummaryChunk(", "))
    out.append(SummaryChunk(f", and {remaining} more"))
    return out


@_register_chunks_coalescer(Action.ACCESS_GRANTED)
def _cc_access_granted(entries: list[AuditLogEntry], principals: Principals) -> list[SummaryChunk]:
    perm, _ptype = _granted_run_key(entries[0])
    target_chunks = _principal_chunks_for(entries, principals, from_field="new_value")
    return [SummaryChunk(f"granted {perm} access to "), *_join_principal_chunks(target_chunks)]


@_register_chunks_coalescer(Action.ACCESS_REVOKED)
def _cc_access_revoked(entries: list[AuditLogEntry], principals: Principals) -> list[SummaryChunk]:
    perm, _ptype = _revoked_run_key(entries[0])
    target_chunks = _principal_chunks_for(entries, principals, from_field="previous_value")
    return [
        SummaryChunk(f"revoked {perm} access from "),
        *_join_principal_chunks(target_chunks),
    ]


# ---- invitation.created / invitation.revoked -------------------------------


def _invitation_created_key(entry: AuditLogEntry) -> str:
    return str(_as_dict(entry.new_value).get("permission", ""))


def _invitation_revoked_key(entry: AuditLogEntry) -> str:
    return str(_as_dict(entry.previous_value).get("permission", ""))


def _extends_invitation_created(prev: AuditLogEntry, nxt: AuditLogEntry) -> bool:
    return _invitation_created_key(prev) == _invitation_created_key(nxt)


def _extends_invitation_revoked(prev: AuditLogEntry, nxt: AuditLogEntry) -> bool:
    return _invitation_revoked_key(prev) == _invitation_revoked_key(nxt)


def _emails_from(entries: list[AuditLogEntry], *, from_field: str) -> list[str]:
    out: list[str] = []
    for entry in entries:
        payload = entry.new_value if from_field == "new_value" else entry.previous_value
        email = _as_dict(payload).get("email")
        if email:
            out.append(str(email))
    return out


@_register_coalescer(Action.INVITATION_CREATED, extends=_extends_invitation_created)
def _c_invitation_created(entries: list[AuditLogEntry], _labels: PrincipalLabels) -> str:
    perm = _invitation_created_key(entries[0]) or "?"
    targets = _emails_from(entries, from_field="new_value")
    if targets:
        return f"invited {_format_label_list(targets)} with {perm} access"
    return f"invited {len(entries)} people with {perm} access"


@_register_coalescer(Action.INVITATION_REVOKED, extends=_extends_invitation_revoked)
def _c_invitation_revoked(entries: list[AuditLogEntry], _labels: PrincipalLabels) -> str:
    targets = _emails_from(entries, from_field="previous_value")
    if targets:
        return f"revoked pending invitations for {_format_label_list(targets)}"
    return f"revoked {len(entries)} pending invitations"


# ---- publication retry storms ----------------------------------------------


@_register_coalescer(Action.PUBLICATION_EXPORT_FAILED)
def _c_publication_export_failed(entries: list[AuditLogEntry], _labels: PrincipalLabels) -> str:
    return f"publication export failed {len(entries)} times"


@_register_coalescer(Action.PUBLICATION_GIT_PUSH_FAILED)
def _c_publication_git_push_failed(entries: list[AuditLogEntry], _labels: PrincipalLabels) -> str:
    return f"publication push failed {len(entries)} times"


def summary_for(entry: AuditLogEntry, principal_labels: PrincipalLabels | None = None) -> str:
    """Human-readable summary for an audit row.

    ``principal_labels`` resolves user/group pks for access events. If
    unset (or the pk is missing from it), access formatters fall back to
    a generic "a user" / "a group" phrasing.

    Falls back to the raw action string for any action that lacks an
    explicit formatter, so a newly-added action degrades to "advisory.foo"
    rather than crashing the timeline.
    """
    fmt = _FORMATTERS.get(entry.action)
    if fmt is None:
        return entry.action
    labels = principal_labels or {}
    try:
        return fmt(entry, labels)
    except Exception:
        return entry.action


# A bare email token inside summary prose, bounded by whitespace/commas.
# Used to redact the email a non-owner would otherwise read in an
# invitation event ("invited bob@example.org …"), which — unlike access
# events — has no user principal to render as a (masked) chip.
_EMAIL_IN_PROSE = re.compile(r"[^\s,]+@[^\s,]+")


def _redact_chunk_emails(chunks: list[SummaryChunk]) -> list[SummaryChunk]:
    """Mask any email in a *pure-text* chunk (INV-PRIVACY-4).

    Principal (user/group) chunks are left untouched — a user chunk renders
    through ``{% user_chip %}`` which does its own owner-gated masking, and a
    group chunk carries a name, not an email.
    """
    out: list[SummaryChunk] = []
    for c in chunks:
        if c.user is None and c.group is None and "@" in c.text:
            out.append(
                SummaryChunk(text=_EMAIL_IN_PROSE.sub(lambda m: mask_email(m.group(0)), c.text))
            )
        else:
            out.append(c)
    return out


def summary_chunks_for(
    entry: AuditLogEntry,
    principals: Principals | None = None,
) -> list[SummaryChunk]:
    """Renderable form of :func:`summary_for`: a list of chunks.

    For actions whose prose embeds a principal name worth rendering as a
    chip (currently ACCESS_GRANTED / ACCESS_REVOKED), returns a mix of
    text and principal chunks. Every other action degrades to a single
    text chunk whose ``text`` equals ``summary_for(entry, ...)``, so the
    template can iterate uniformly.

    Joining ``c.text for c in result`` yields the same string as
    ``summary_for`` would produce — chunks never invent prose.
    """
    fmt = _CHUNK_FORMATTERS.get(entry.action)
    if fmt is not None:
        try:
            return fmt(entry, principals or {})
        except Exception:
            pass
    # Fall through to the string formatter wrapped as one text chunk.
    labels: PrincipalLabels = {k: v.label for k, v in principals.items()} if principals else {}
    return [SummaryChunk(text=summary_for(entry, principal_labels=labels))]


@dataclass(frozen=True)
class TimelineEvent:
    """View-friendly wrapper around :class:`AuditLogEntry`.

    ``actor`` is the live User (or ``None`` for system events); templates
    render the chip via ``{% user_chip event.actor fallback="system" %}``.
    ``actor_label`` is kept as the plain-string fallback used inside
    coalesced summaries and in non-HTML contexts (logs, tests).

    ``summary`` is the joined plain-text prose; ``summary_chunks`` is the
    same text broken into renderable pieces so the template can swap in
    a ``{% user_chip %}`` for principal mentions on access events.
    Non-access rows have a single text chunk whose ``text == summary``.
    """

    id: int
    actor: object | None
    actor_label: str
    action: str
    created_at: datetime
    summary: str
    summary_chunks: list[SummaryChunk]

    @classmethod
    def from_entry(
        cls,
        entry: AuditLogEntry,
        principal_labels: PrincipalLabels | None = None,
        *,
        principals: Principals | None = None,
        show_emails: bool = True,
    ) -> TimelineEvent:
        actor = entry.actor
        actor_label = actor.display_label(fallback="unknown") if actor is not None else "system"
        labels = principal_labels
        if labels is None and principals is not None:
            labels = {k: v.label for k, v in principals.items()}
        chunks = summary_chunks_for(entry, principals=principals)
        if not show_emails:
            chunks = _redact_chunk_emails(chunks)
        return cls(
            id=entry.pk,
            actor=actor,
            actor_label=actor_label,
            action=entry.action,
            created_at=entry.created_at,
            summary=summary_for(entry, principal_labels=labels),
            summary_chunks=chunks,
        )

    @classmethod
    def from_run(
        cls,
        entries: list[AuditLogEntry],
        principal_labels: PrincipalLabels | None = None,
        *,
        principals: Principals | None = None,
        show_emails: bool = True,
    ) -> TimelineEvent:
        """Wrap a coalesced run of entries into a single timeline event.

        Uses the latest entry's id and timestamp (so the row sorts to the
        end of the run) and the actor of the run (all entries share the
        same actor by construction).
        """
        if len(entries) == 1:
            return cls.from_entry(
                entries[0],
                principal_labels=principal_labels,
                principals=principals,
                show_emails=show_emails,
            )
        last = entries[-1]
        actor = last.actor
        actor_label = actor.display_label(fallback="unknown") if actor is not None else "system"
        labels = principal_labels
        if labels is None and principals is not None:
            labels = {k: v.label for k, v in principals.items()}
        chunks = coalesced_chunks(entries, principals or {})
        if not show_emails:
            chunks = _redact_chunk_emails(chunks)
        return cls(
            id=last.pk,
            actor=actor,
            actor_label=actor_label,
            action=last.action,
            created_at=last.created_at,
            summary=coalesced_summary(entries, labels or {}),
            summary_chunks=chunks,
        )
