"""Comment markdown rendering, mention extraction, and write helpers.

Markdown is rendered with ``markdown-it-py`` and post-sanitised by
``bleach``. The allowlist is intentionally narrow — no images, no inline
HTML, no scripts. Tightening here applies retroactively to all stored
comments because we never store rendered HTML.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

import bleach
from django.db import transaction
from django.db.models import Max
from django.utils import timezone
from markdown_it import MarkdownIt

from accounts.models import User
from advisories import permissions as perms
from advisories.models import Advisory
from audit.models import Action
from audit.services import record

from .models import AdvisoryComment, CommentVersion

# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

_MD = MarkdownIt("commonmark", {"breaks": True, "linkify": True}).enable("table")

_ALLOWED_TAGS = {
    "p",
    "br",
    "strong",
    "em",
    "u",
    "code",
    "pre",
    "blockquote",
    "hr",
    "ul",
    "ol",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "a",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
}
_ALLOWED_ATTRS = {"a": ["href", "title", "rel"]}
_ALLOWED_PROTOCOLS = ["http", "https", "mailto"]


def render_markdown(body: str) -> str:
    """Render markdown to a sanitized HTML fragment safe for inclusion in templates."""
    raw_html = _MD.render(body or "")
    cleaner = bleach.Cleaner(
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=_ALLOWED_PROTOCOLS,
        strip=True,
    )
    cleaned = cleaner.clean(raw_html)
    # Add rel="nofollow noopener" to all links via bleach.linkify-style postprocess.
    cleaned = re.sub(
        r"<a ([^>]*?)>",
        lambda m: _augment_anchor(m.group(1)),
        cleaned,
    )
    return cleaned


def _augment_anchor(attrs: str) -> str:
    if "rel=" in attrs.lower():
        return f"<a {attrs}>"
    return f'<a {attrs} rel="nofollow noopener">'


# ---------------------------------------------------------------------------
# Mentions
# ---------------------------------------------------------------------------

# A mention is "@" followed by an email-local-style token. We resolve them
# against the User table by exact email or by display_name.
_MENTION_RE = re.compile(r"(?<![\w.])@([A-Za-z0-9_.\-+]+(?:@[A-Za-z0-9_.\-]+)?)")


def extract_mentions(body: str) -> list[str]:
    if not body:
        return []
    return [m.group(1) for m in _MENTION_RE.finditer(body)]


def resolve_mentioned_users(body: str) -> list[User]:
    """Resolve ``@handle`` mentions in body to User instances.

    A handle is matched against either the full email (``@alice@example.org``)
    or the local-part of an email (``@alice`` matches ``alice@anything``).
    Duplicates and unresolvable handles are dropped silently.
    """
    handles = extract_mentions(body)
    if not handles:
        return []
    from django.db.models import Q

    full = {h for h in handles if "@" in h}
    locals_ = {h for h in handles if "@" not in h}
    q = Q()
    for handle in full:
        q |= Q(email__iexact=handle)
    for handle in locals_:
        q |= Q(email__istartswith=f"{handle}@")
    if not q.children:
        return []
    return list(User.objects.filter(q).distinct())


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------


def add_comment(
    advisory: Advisory,
    *,
    author: User,
    body: str,
    internal: bool = False,
) -> AdvisoryComment:
    from django.core.exceptions import PermissionDenied

    if not perms.can_comment(author, advisory):
        raise PermissionDenied("You cannot comment on this advisory.")
    effective_internal = bool(internal)
    if effective_internal and not perms.can_post_internal_comment(author, advisory):
        raise PermissionDenied("You cannot post internal comments on this advisory.")
    with transaction.atomic():
        comment = AdvisoryComment.objects.create(
            advisory=advisory,
            author=author,
            body=body,
            is_internal=effective_internal,
        )
        CommentVersion.objects.create(comment=comment, version=1, body=body, editor=author)
    record(
        action=Action.COMMENT_CREATED,
        actor=author,
        advisory=advisory,
        comment=comment,
        new_value={
            "body_length": len(body),
            "is_internal": effective_internal,
        },
    )
    return comment


def edit_comment(comment: AdvisoryComment, *, by: User, new_body: str) -> AdvisoryComment:
    if not _can_edit_own_comment(comment, by):
        from django.core.exceptions import PermissionDenied

        raise PermissionDenied("You cannot edit this comment.")
    previous_len = len(comment.body)
    with transaction.atomic():
        # Serialize concurrent edits on the same comment so two callers
        # never compute the same next version number.
        AdvisoryComment.objects.select_for_update().filter(pk=comment.pk).first()
        comment.body = new_body
        comment.edited_at = timezone.now()
        comment.save(update_fields=["body", "edited_at"])
        next_version = (
            CommentVersion.objects.filter(comment=comment).aggregate(m=Max("version"))["m"] or 0
        ) + 1
        CommentVersion.objects.create(
            comment=comment, version=next_version, body=new_body, editor=by
        )
    record(
        action=Action.COMMENT_EDITED,
        actor=by,
        advisory=comment.advisory,
        comment=comment,
        previous_value={"body_length": previous_len},
        new_value={"body_length": len(new_body)},
    )
    return comment


def history_for_comment(comment: AdvisoryComment, *, viewer: User) -> list[CommentVersion]:
    """Return the ordered version history visible to ``viewer``.

    Re-checks view permission on the parent advisory and internal-comment
    visibility — the history endpoint is reachable by URL, so we do not
    rely on the caller having already gated access. Returns an empty list
    when the comment is redacted, matching ``visible_body()`` semantics.
    """
    from django.core.exceptions import PermissionDenied

    if not perms.can_view(viewer, comment.advisory):
        raise PermissionDenied("You do not have access to this advisory.")
    if comment.is_internal and not perms.can_see_internal_comment(viewer, comment.advisory):
        raise PermissionDenied("You cannot view this comment's history.")
    if comment.is_redacted:
        return []
    return list(
        CommentVersion.objects.filter(comment=comment)
        .select_related("editor")
        .prefetch_related("editor__groups")
        .order_by("version")
    )


COMMENT_HISTORY_PAGE_SIZE = 10


def history_with_diffs_for_comment(
    comment: AdvisoryComment,
    *,
    viewer: User,
    page_size: int = COMMENT_HISTORY_PAGE_SIZE,
    before_version_id: int | None = None,
) -> dict:
    """Return one page of the comment's edit history with word-level diffs.

    Mirrors :func:`advisories.services.details_history` — same return
    shape, same cursor semantics. Permission gating + redaction are
    delegated to :func:`history_for_comment`; an empty result here means
    either "no history" or "you can't see it".

    Returned shape::

        {"entries":     [{"version": CommentVersion, "diff_chunks": ...,
                          "is_initial": bool, "full_markdown": str}, ...],
         "next_cursor": int | None,
         "total_kept":  int}

    Unlike advisories, every ``CommentVersion`` past v1 is a body change
    by construction (``edit_comment`` only appends on a real edit), so
    nothing is filtered out — every fetched version becomes an entry.
    """
    from common.text_diff import text_diff

    versions = history_for_comment(comment, viewer=viewer)
    if not versions:
        return {"entries": [], "next_cursor": None, "total_kept": 0}

    # Materialise the kept list (no diffs yet); newest-first for display.
    kept: list[tuple] = []  # (version, body, prev_body_or_None, is_initial)
    prev_body: str | None = None
    for version in versions:
        kept.append((version, version.body, prev_body, prev_body is None))
        prev_body = version.body
    kept.reverse()
    total_kept = len(kept)

    start = 0
    if before_version_id is not None:
        for idx, (version, _body, _prev, _initial) in enumerate(kept):
            if version.pk == before_version_id:
                start = idx + 1
                break
        else:
            return {"entries": [], "next_cursor": None, "total_kept": total_kept}

    slice_end = start + page_size
    slice_ = kept[start:slice_end]

    entries: list[dict] = []
    for version, body, prev_kept_body, is_initial in slice_:
        entries.append(
            {
                "version": version,
                "diff_chunks": [] if is_initial else text_diff(prev_kept_body or "", body),
                "is_initial": is_initial,
                "full_markdown": body,
            }
        )

    next_cursor = entries[-1]["version"].pk if entries and slice_end < total_kept else None
    return {"entries": entries, "next_cursor": next_cursor, "total_kept": total_kept}


def redact_comment(comment: AdvisoryComment, *, by: User) -> AdvisoryComment:
    if not _can_redact(comment, by):
        from django.core.exceptions import PermissionDenied

        raise PermissionDenied("You cannot redact this comment.")
    comment.redacted_at = timezone.now()
    comment.redacted_by = by
    comment.save(update_fields=["redacted_at", "redacted_by"])
    record(
        action=Action.COMMENT_REDACTED,
        actor=by,
        advisory=comment.advisory,
        comment=comment,
    )
    return comment


def _can_edit_own_comment(comment: AdvisoryComment, user: User) -> bool:
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if comment.is_redacted:
        return False
    return comment.author_id == user.pk


def _can_redact(comment: AdvisoryComment, user: User) -> bool:
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if comment.is_redacted:
        return False
    if perms.is_global_admin(user):
        return True
    return comment.author_id == user.pk


# ---------------------------------------------------------------------------
# Comment list
# ---------------------------------------------------------------------------


def comments_for_advisory(advisory: Advisory, *, viewer: User) -> Iterable[AdvisoryComment]:
    """Return the advisory's comments ordered by ``created_at``.

    Internal comments are filtered out for viewers who lack collaborator+
    access. The filter runs at the DB layer so a template change can't
    accidentally leak hidden rows.
    """
    base = AdvisoryComment.objects.select_related("author").prefetch_related("author__groups")
    if not perms.can_see_internal_comment(viewer, advisory):
        base = base.exclude(is_internal=True)
    return base.filter(advisory=advisory).order_by("created_at")


# ---------------------------------------------------------------------------
# Unified timeline (comments + audit events)
# ---------------------------------------------------------------------------


def advisory_timeline(advisory: Advisory, *, viewer: User) -> list[dict]:
    """Merge comments and visible audit events into one chronological list.

    Each item is a dict ``{"kind": "comment"|"event", "ts": datetime,
    "obj": ...}``. Comments tie-break before events with the same
    timestamp so the very first comment is never visually pushed below
    a same-instant ``advisory.created`` event.

    Adjacent same-actor / same-action events on the coalescing whitelist
    (``advisories.timeline.can_coalesce``) collapse into a single rolled-up
    row using the latest entry's timestamp. A comment or any
    non-coalescable event between two otherwise-mergable entries breaks
    the run, anchoring the conversation to the right state.
    """
    from advisories.timeline import (
        TimelineEvent,
        can_coalesce,
        can_extend_run,
        events_for_advisory,
        resolve_principals,
    )

    # Build a single sorted list of raw items first — comments stay as
    # AdvisoryComment instances, events stay as AuditLogEntry instances —
    # so the coalescing pass below can look at action / actor_id / payload
    # without going through the wrapper.
    raw: list[tuple] = []
    for comment in comments_for_advisory(advisory, viewer=viewer):
        raw.append((comment.created_at, "comment", comment))

    events = list(events_for_advisory(advisory, viewer=viewer))
    principals = resolve_principals(events)
    for entry in events:
        raw.append((entry.created_at, "event", entry))

    raw.sort(key=lambda x: (x[0], 0 if x[1] == "comment" else 1))

    out: list[dict] = []
    i = 0
    while i < len(raw):
        ts, kind, obj = raw[i]
        if kind == "comment":
            out.append({"kind": "comment", "ts": ts, "obj": obj})
            i += 1
            continue
        # Greedily extend a coalescable run starting at i.
        run: list = [obj]
        j = i + 1
        if can_coalesce(obj.action):
            while j < len(raw) and raw[j][1] == "event" and can_extend_run(run[-1], raw[j][2]):
                run.append(raw[j][2])
                j += 1
        wrapped = TimelineEvent.from_run(run, principals=principals)
        out.append({"kind": "event", "ts": wrapped.created_at, "obj": wrapped})
        i = j
    return out
