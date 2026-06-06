"""Tiny hand-rolled JSON serializers.

We deliberately avoid DRF for what is a small, internal-only API. Each
serializer is a function ``to_dict(obj) -> dict``. They mirror the model
fields the API consumer needs — no auto-discovery, no model coupling.
"""

from __future__ import annotations

from typing import Any

from django.urls import reverse

from accounts.utils import mask_email


def advisory_to_dict(advisory) -> dict[str, Any]:
    return {
        "advisory_id": advisory.advisory_id,
        "project": {
            "id": str(advisory.project.id),
            "slug": advisory.project.slug,
            "name": advisory.project.name,
            "is_mature_publisher": advisory.project.is_mature_publisher,
        },
        "state": advisory.state,
        "review_status": advisory.review_status,
        "summary": advisory.summary,
        "details": advisory.details,
        "aliases": list(advisory.aliases or []),
        "references": list(advisory.references or []),
        "affected": list(advisory.affected or []),
        "severity": list(advisory.severity or []),
        "cwe_ids": list(advisory.cwe_ids or []),
        "credits": list(advisory.credits or []),
        "republish_required": advisory.republish_required,
        "withdrawn_reason": advisory.withdrawn_reason,
        "dismissed_reason": advisory.dismissed_reason,
        "created_at": _isoformat(advisory.created_at),
        "modified_at": _isoformat(advisory.modified_at),
        "published_at": _isoformat(advisory.published_at),
        "submitted_for_review_at": _isoformat(advisory.submitted_for_review_at),
        "url": reverse("advisories:detail", args=[advisory.advisory_id]),
    }


def advisory_summary_to_dict(advisory) -> dict[str, Any]:
    """Compact representation for list endpoints."""
    return {
        "advisory_id": advisory.advisory_id,
        "project": advisory.project.slug,
        "state": advisory.state,
        "review_status": advisory.review_status,
        "summary": advisory.summary,
        "modified_at": _isoformat(advisory.modified_at),
        "published_at": _isoformat(advisory.published_at),
        "republish_required": advisory.republish_required,
    }


def comment_to_dict(comment, *, show_emails: bool = False) -> dict[str, Any]:
    author = None
    if comment.author_id:
        author = comment.author.email if show_emails else mask_email(comment.author.email)
    return {
        "id": comment.pk,
        "author": author,
        "body": comment.visible_body(),
        "is_redacted": comment.is_redacted,
        "is_internal": comment.is_internal,
        "created_at": _isoformat(comment.created_at),
        "edited_at": _isoformat(comment.edited_at),
    }


def grant_to_dict(grant, *, show_emails: bool = False) -> dict[str, Any]:
    principal = grant.principal()
    label = None
    if principal is not None:
        label = getattr(principal, "email", None) or getattr(principal, "name", None)
        if not show_emails:
            # mask_email no-ops on group names (no "@"), so a group label
            # passes through unchanged; only a user's email gets redacted.
            label = mask_email(label)
    return {
        "id": grant.pk,
        "principal_type": grant.principal_type,
        "principal_id": grant.principal_id,
        "principal_label": label,
        "permission": grant.permission,
        "created_at": _isoformat(grant.created_at),
    }


def invitation_to_dict(invitation, *, show_emails: bool = False) -> dict[str, Any]:
    return {
        "id": invitation.pk,
        "email": invitation.email if show_emails else mask_email(invitation.email),
        "permission": invitation.permission,
        "expires_at": _isoformat(invitation.expires_at),
        "redeemed_at": _isoformat(invitation.redeemed_at),
    }


def publication_task_to_dict(task) -> dict[str, Any]:
    return {
        "id": task.pk,
        "advisory_id": task.advisory.advisory_id,
        "status": task.status,
        "attempts": task.attempts,
        "commit_sha": task.commit_sha,
        "last_error": task.last_error,
        "created_at": _isoformat(task.created_at),
        "started_at": _isoformat(task.started_at),
        "finished_at": _isoformat(task.finished_at),
        "artifacts": [
            {"kind": a.kind, "path": a.path}
            for a in getattr(task, "_prefetched_artifacts", task.artifacts.all())
        ],
    }


def cve_task_to_dict(task, *, show_emails: bool = False) -> dict[str, Any]:
    def _email(user, has_id):
        if not has_id:
            return None
        return user.email if show_emails else mask_email(user.email)

    return {
        "id": task.pk,
        "advisory_id": task.advisory.advisory_id,
        "status": task.status,
        "cve_id": task.cve_id,
        "assignee": _email(task.assignee, task.assignee_id),
        "requested_by": _email(task.requested_by, task.requested_by_id),
        "created_at": _isoformat(task.created_at),
        "finished_at": _isoformat(task.finished_at),
    }


def review_task_to_dict(task, *, show_emails: bool = False) -> dict[str, Any]:
    def _email(user, has_id):
        if not has_id:
            return None
        return user.email if show_emails else mask_email(user.email)

    return {
        "id": task.pk,
        "advisory_id": task.advisory.advisory_id,
        "status": task.status,
        "submitted_by": _email(task.submitted_by, task.submitted_by_id),
        "reviewer": _email(task.reviewer, task.reviewer_id),
        "decision_notes": task.decision_notes,
        "created_at": _isoformat(task.created_at),
        "decided_at": _isoformat(task.decided_at),
    }


def _isoformat(value) -> str | None:
    return value.isoformat() if value is not None else None
