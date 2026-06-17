"""HTMX endpoints for the comment UI.

Every endpoint enforces authorization through ``advisories.permissions``
and ``comments.services``; templates only display.
"""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from advisories import permissions as perms
from advisories.models import Advisory
from common.enqueue import safe_enqueue
from common.ratelimit import html_ratelimit

from . import services
from .forms import CommentEditForm, CommentForm
from .models import AdvisoryComment


def _email_visibility(request, advisory) -> dict:
    """Per-advisory override for the ``user_chip`` email-visibility flag.

    The context processor defaults this to global-admin-only; advisory-scoped
    fragments must set the precise per-advisory value so a project security-team
    owner sees emails on their own advisory's rows (``INV-PRIVACY-4``).
    """
    return {"viewer_can_see_emails": perms.can_see_user_emails(request.user, advisory)}


@login_required
@require_http_methods(["GET"])
def comment_thread(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_view(request.user, advisory):
        raise PermissionDenied("You do not have access to this advisory.")
    return render(
        request,
        "comments/_thread.html",
        {
            "advisory": advisory,
            **_email_visibility(request, advisory),
            "thread": services.comments_for_advisory(advisory, viewer=request.user),
            "form": CommentForm(),
            "can_comment": perms.can_comment(request.user, advisory),
            "can_post_internal": perms.can_post_internal_comment(request.user, advisory),
        },
    )


@login_required
@require_http_methods(["GET"])
def timeline(request, advisory_id: str):
    """HTMX fragment: comments + visible audit events, chronologically merged."""
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_view(request.user, advisory):
        raise PermissionDenied("You do not have access to this advisory.")
    return render(
        request,
        "comments/_timeline.html",
        {
            "advisory": advisory,
            "timeline": services.advisory_timeline(advisory, viewer=request.user),
            **_email_visibility(request, advisory),
            "form": CommentForm(),
            "can_comment": perms.can_comment(request.user, advisory),
            "can_post_internal": perms.can_post_internal_comment(request.user, advisory),
        },
    )


@login_required
@require_http_methods(["POST"])
@html_ratelimit(rate="30/m")
def comment_create(request, advisory_id: str):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_comment(request.user, advisory):
        raise PermissionDenied("You cannot comment on this advisory.")
    form = CommentForm(request.POST)
    if not form.is_valid():
        return render(
            request,
            "comments/_form.html",
            {"advisory": advisory, "form": form},
            status=400,
        )
    body = form.cleaned_data["body"]
    internal = bool(form.cleaned_data.get("is_internal", False))
    try:
        with transaction.atomic():
            comment = services.add_comment(
                advisory,
                author=request.user,
                body=body,
                internal=internal,
            )
            # Queue email notifications after the DB commit so workers see the row.
            transaction.on_commit(lambda: _queue_comment_email(advisory.pk, comment.pk))
    except ValueError as exc:
        form.add_error(None, str(exc))
        return render(
            request,
            "comments/_form.html",
            {"advisory": advisory, "form": form},
            status=400,
        )
    # Return the rendered timeline so HTMX can swap it in
    return render(
        request,
        "comments/_timeline.html",
        {
            "advisory": advisory,
            "timeline": services.advisory_timeline(advisory, viewer=request.user),
            **_email_visibility(request, advisory),
            "form": CommentForm(),
            "can_comment": perms.can_comment(request.user, advisory),
            "can_post_internal": perms.can_post_internal_comment(request.user, advisory),
        },
    )


def _queue_comment_email(advisory_id: int, comment_id: int) -> None:
    from notifications.tasks import send_comment_email

    safe_enqueue(send_comment_email, advisory_id, comment_id)


def _queue_comment_mention_email(
    advisory_id: int,
    comment_id: int,
    recipient_ids: list[int],
    group_ids: list[int] | None = None,
) -> None:
    from notifications.tasks import send_comment_mention_email

    safe_enqueue(
        send_comment_mention_email, advisory_id, comment_id, recipient_ids, group_ids or []
    )


@login_required
@require_http_methods(["GET", "POST"])
def comment_edit(request, advisory_id: str, comment_id: int):
    comment = get_object_or_404(AdvisoryComment, pk=comment_id, advisory__advisory_id=advisory_id)
    if not perms.can_view(request.user, comment.advisory):
        raise PermissionDenied("You do not have access to this advisory.")
    if comment.author_id != request.user.pk:
        raise PermissionDenied("You can only edit your own comments.")
    if comment.is_redacted:
        raise PermissionDenied("Redacted comments cannot be edited.")
    # Demoted-author guard: a collaborator who posted an internal comment
    # and is later dropped to viewer can no longer see — and therefore
    # cannot edit — the comment. Keeps the "you can only touch what you
    # can see" invariant.
    if comment.is_internal and not perms.can_see_internal_comment(request.user, comment.advisory):
        raise PermissionDenied("You cannot edit this comment.")

    if request.method == "POST":
        form = CommentEditForm(request.POST, instance=comment)
        if form.is_valid():
            new_body = form.cleaned_data["body"]
            # The pre-edit body must come from the DB: validating the ModelForm
            # may have already mutated ``comment.body`` in memory, so it is no
            # longer a reliable source of the previous text.
            old_body = AdvisoryComment.objects.values_list("body", flat=True).get(pk=comment.pk)
            with transaction.atomic():
                services.edit_comment(comment, by=request.user, new_body=new_body)
                # Notify only the recipients this edit *adds* — unchanged
                # mentions were already told when the comment was first posted.
                added = services.resolve_mention_recipient_ids(
                    new_body
                ) - services.resolve_mention_recipient_ids(old_body)
                # Newly-mentioned group ids let an edit that adds a @team
                # mention reach that team's shadow roster members (absent from
                # user.groups, so never in ``added``). A team mention that was
                # already present is not in the delta → its shadows aren't
                # re-notified.
                added_group_ids = {g.pk for g in services.resolve_mentioned_groups(new_body)} - {
                    g.pk for g in services.resolve_mentioned_groups(old_body)
                }
                if added or added_group_ids:
                    advisory_pk = comment.advisory.pk
                    comment_pk = comment.pk
                    ids = sorted(added)
                    group_ids = sorted(added_group_ids)
                    transaction.on_commit(
                        lambda: _queue_comment_mention_email(
                            advisory_pk, comment_pk, ids, group_ids
                        )
                    )
            return render(
                request,
                "comments/_comment.html",
                {
                    "comment": comment,
                    "advisory": comment.advisory,
                    "request": request,
                    **_email_visibility(request, comment.advisory),
                },
            )
    else:
        form = CommentEditForm(instance=comment)
    return render(
        request,
        "comments/_edit.html",
        {"comment": comment, "form": form, "advisory": comment.advisory},
    )


@login_required
@require_http_methods(["GET"])
def comment_history(request, advisory_id: str, comment_id: int):
    comment = get_object_or_404(AdvisoryComment, pk=comment_id, advisory__advisory_id=advisory_id)

    before_raw = request.GET.get("before")
    try:
        before_id = int(before_raw) if before_raw else None
    except ValueError:
        before_id = None

    page = services.history_with_diffs_for_comment(
        comment, viewer=request.user, before_version_id=before_id
    )
    template = (
        "common/_history_page.html" if before_id is not None else "comments/_history_drawer.html"
    )
    return render(
        request,
        template,
        {
            "comment": comment,
            "advisory": comment.advisory,
            **_email_visibility(request, comment.advisory),
            "entries": page["entries"],
            "next_cursor": page["next_cursor"],
            "load_more_url": reverse(
                "comments:history", args=[comment.advisory.advisory_id, comment.pk]
            ),
            "is_first_page": before_id is None,
        },
    )


@login_required
@require_http_methods(["POST"])
def comment_redact(request, advisory_id: str, comment_id: int):
    comment = get_object_or_404(AdvisoryComment, pk=comment_id, advisory__advisory_id=advisory_id)
    if not perms.can_view(request.user, comment.advisory):
        raise PermissionDenied("You do not have access to this advisory.")
    if comment.is_internal and not perms.can_see_internal_comment(request.user, comment.advisory):
        raise PermissionDenied("You cannot redact this comment.")
    services.redact_comment(comment, by=request.user)
    return render(
        request,
        "comments/_comment.html",
        {
            "comment": comment,
            "advisory": comment.advisory,
            "request": request,
            **_email_visibility(request, comment.advisory),
        },
    )
