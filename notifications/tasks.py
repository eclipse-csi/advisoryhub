"""Celery tasks for advisory email notifications.

Every task re-resolves recipients via :mod:`notifications.recipients` so
that revoked-access users never receive private content even if the event
was queued before their access was revoked.

Email bodies are rendered from templates under ``templates/notifications/``.
For draft/dismissed advisories the *content* of the body is intentionally
sparse — recipients are told what changed and given a link to the
authenticated app — to avoid leaking sensitive details into mail providers
that may live outside the recipient's organisation.
"""

from __future__ import annotations

import logging

from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import reverse

from advisories.models import Advisory
from audit.models import Action
from audit.services import record as audit_record

from . import services
from .models import NotificationKind
from .recipients import _absolute_url, filter_for_event, notification_footer

log = logging.getLogger(__name__)


def _advisory_url(advisory: Advisory) -> str:
    return _absolute_url(reverse("advisories:detail", args=[advisory.advisory_id]))


def _send_one(
    *,
    recipient,
    subject: str,
    template: str,
    context: dict,
    kind: str,
    advisory: Advisory,
    comment_id: int | None = None,
    summary: str = "",
) -> None:
    # Merge the per-recipient footer ("why am I getting this?") without mutating
    # the caller's ``context`` — the triage task reuses one dict across every
    # recipient, so per-recipient data must not leak between sends.
    render_context = {**context, **notification_footer(recipient, advisory, kind=kind)}
    text_body = render_to_string(f"notifications/{template}.txt", render_context)
    html_body = render_to_string(f"notifications/{template}.html", render_context)
    send_mail(
        subject=subject,
        message=text_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient.email],
        html_message=html_body,
    )
    # Record the in-app inbox row only after a successful send. A DB hiccup
    # here must never suppress an email that already went out, so it is
    # swallowed — the email is the source of truth; the inbox merely mirrors it.
    try:
        services.record_delivery(
            recipient=recipient,
            advisory=advisory,
            kind=kind,
            subject=subject,
            summary=summary,
            comment_id=comment_id,
        )
    except Exception:  # pragma: no cover — inbox persistence is best-effort
        log.exception("Failed to record notification delivery for %s", recipient.email)
    # Mirror the delivery into the ephemeral access log so admins get a single
    # system-wide "what notifications went out" view. Best-effort for the same
    # reason as the inbox row above: the email already went out and must never
    # be undone by a logging failure. Actor is the system (no request in the
    # worker); the recipient lives in metadata (the access log has no recipient
    # column) — findable via the metadata search, and retention-pruned /
    # forget_user-erasable like the rest of that table.
    try:
        audit_record(
            action=Action.NOTIFICATION_SENT,
            actor=None,
            advisory=advisory,
            metadata={
                "kind": str(kind),
                "recipient_id": recipient.pk,
                "recipient_email": recipient.email,
                **({"comment_id": comment_id} if comment_id else {}),
            },
        )
    except Exception:  # pragma: no cover — audit is best-effort
        log.exception("Failed to audit notification delivery for %s", recipient.email)


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


@shared_task(name="notifications.send_advisory_event_email")
def send_advisory_event_email(advisory_id: int, event: str) -> int:
    """Notify watchers of an advisory lifecycle event.

    ``event`` ∈ {advisory_created, advisory_submitted_for_review,
    advisory_review_withdrawn, advisory_published,
    publication_export_status}.
    """
    try:
        advisory = Advisory.objects.get(pk=advisory_id)
    except Advisory.DoesNotExist:
        return 0
    recipients = filter_for_event(advisory, event=event)
    sent = 0
    subject_map = {
        "advisory_created": f"[{advisory.advisory_id}] new advisory created",
        "advisory_submitted_for_review": f"[{advisory.advisory_id}] submitted for review",
        "advisory_published": f"[{advisory.advisory_id}] published",
        "publication_export_status": f"[{advisory.advisory_id}] publication status update",
    }
    for user in recipients:
        try:
            _send_one(
                recipient=user,
                subject=subject_map.get(event, f"[{advisory.advisory_id}] {event}"),
                template="advisory_event",
                context={
                    "advisory": advisory,
                    "event": event,
                    "url": _advisory_url(advisory),
                },
                kind=event,
                advisory=advisory,
            )
            sent += 1
        except Exception:  # pragma: no cover — never let email errors crash workflows
            log.exception("Failed to send %s notification to %s", event, user.email)
    return sent


@shared_task(name="notifications.send_comment_email")
def send_comment_email(advisory_id: int, comment_id: int) -> int:
    """Notify watchers (per their preferences) of a new comment.

    Mentioned users in particular get the notification regardless of their
    comment_mode (handled by ``filter_for_event``'s 'mention' branch).
    """
    from comments.models import AdvisoryComment
    from comments.services import resolve_mention_recipient_ids, resolve_mentioned_groups

    try:
        advisory = Advisory.objects.get(pk=advisory_id)
        comment = AdvisoryComment.objects.get(pk=comment_id)
    except (Advisory.DoesNotExist, AdvisoryComment.DoesNotExist):
        return 0

    # Includes direct @user mentions and the members of any @group mention.
    mentioned_ids = sorted(resolve_mention_recipient_ids(comment.body))
    # Group ids let an @team mention also reach the project's shadow roster
    # members (who are not in ``user.groups``); see filter_for_event.
    mentioned_group_ids = [g.pk for g in resolve_mentioned_groups(comment.body)]
    internal = comment.is_internal

    # Two-pass: first send "mention" notifications (override the comment_mode),
    # then send "comment" notifications to everyone else. We dedupe so a
    # mentioned user only gets one email. For internal comments, recipients
    # without collaborator+ access are dropped at the filter — they can't see
    # the comment in the app, so they don't get an email about it (mention
    # is *not* allowed to elevate visibility).
    sent_to_ids: set[int] = set()
    sent = 0

    for user in filter_for_event(
        advisory,
        event="mention",
        mentioned_user_ids=mentioned_ids,
        mentioned_group_ids=mentioned_group_ids,
        internal=internal,
    ):
        try:
            _send_one(
                recipient=user,
                subject=f"[{advisory.advisory_id}] you were mentioned",
                template="comment_mention",
                context={"advisory": advisory, "comment": comment, "url": _advisory_url(advisory)},
                kind=NotificationKind.MENTION,
                advisory=advisory,
                comment_id=comment.pk,
            )
            sent_to_ids.add(user.pk)
            sent += 1
        except Exception:  # pragma: no cover
            log.exception("Failed to send mention notification to %s", user.email)

    for user in filter_for_event(
        advisory, event="comment", mentioned_user_ids=mentioned_ids, internal=internal
    ):
        if user.pk in sent_to_ids:
            continue
        try:
            _send_one(
                recipient=user,
                subject=f"[{advisory.advisory_id}] new comment",
                template="comment",
                context={"advisory": advisory, "comment": comment, "url": _advisory_url(advisory)},
                kind=NotificationKind.COMMENT,
                advisory=advisory,
                comment_id=comment.pk,
            )
            sent_to_ids.add(user.pk)
            sent += 1
        except Exception:  # pragma: no cover
            log.exception("Failed to send comment notification to %s", user.email)
    return sent


@shared_task(name="notifications.send_comment_mention_email")
def send_comment_mention_email(
    advisory_id: int,
    comment_id: int,
    recipient_ids: list[int],
    mentioned_group_ids: list[int] | None = None,
) -> int:
    """Notify a *specific* set of users newly @-mentioned by a comment **edit**.

    The edit view computes the delta (mentions added by this edit) and passes
    those user ids here. ``mentioned_group_ids`` carries the *newly*-mentioned
    group ids so an edit that adds a ``@team`` mention reaches the project's
    shadow roster members (who are not in ``user.groups`` and so never appear
    in ``recipient_ids``); a team mention that was already present is not in the
    delta, so its shadows are not re-notified. They are still routed through
    ``filter_for_event(event="mention", …)`` so visibility is re-checked at
    send time (INV-AUTH-1): a passed id whose access was revoked since the
    edit — or who cannot see an internal comment — is dropped. Only the
    ``comment_mention`` template is sent (no second "comment" pass): unchanged
    watchers were already told about the comment when it was first posted.
    """
    from comments.models import AdvisoryComment

    if not recipient_ids and not mentioned_group_ids:
        return 0
    try:
        advisory = Advisory.objects.get(pk=advisory_id)
        comment = AdvisoryComment.objects.get(pk=comment_id)
    except (Advisory.DoesNotExist, AdvisoryComment.DoesNotExist):
        return 0

    sent = 0
    for user in filter_for_event(
        advisory,
        event="mention",
        mentioned_user_ids=list(recipient_ids),
        mentioned_group_ids=list(mentioned_group_ids or []),
        internal=comment.is_internal,
    ):
        try:
            _send_one(
                recipient=user,
                subject=f"[{advisory.advisory_id}] you were mentioned",
                template="comment_mention",
                context={"advisory": advisory, "comment": comment, "url": _advisory_url(advisory)},
                kind=NotificationKind.MENTION,
                advisory=advisory,
                comment_id=comment.pk,
            )
            sent += 1
        except Exception:  # pragma: no cover
            log.exception("Failed to send mention notification to %s", user.email)
    return sent


def _advisory_triage_recipients(advisory, *, admins_only: bool = False) -> list:
    """Resolve recipients for an advisory-triage event at *send* time.

    The unrouted ``unsorted`` sentinel project's ``security_team`` is the
    admin group by construction (see ``projects/migrations/0003``), so the
    project-security-team path Just Works for both routed and unrouted
    advisories — no special case is needed here. The ``admins_only`` shortcut
    is for events that should always reach admins regardless of the
    advisory's current project (e.g. ``advisory_flagged_for_routing``).

    For the project-team path, active **shadow** roster members of the project
    are unioned in (notification-only reach; INV-ROSTER-1). They are *not*
    added to the ``admins_only`` path — shadows are project-team members, not
    admins.
    """
    from accounts.models import User

    if admins_only:
        group_name = settings.OIDC_ADMIN_GROUP
        return list(User.objects.filter(is_active=True, groups__name=group_name).distinct())

    from .recipients import _dedup_users, _roster_shadow_members

    group_name = advisory.project.security_team.name
    team = list(User.objects.filter(is_active=True, groups__name=group_name).distinct())
    return _dedup_users(team, _roster_shadow_members(advisory))


@shared_task(name="notifications.send_advisory_triage_event_email")
def send_advisory_triage_event_email(advisory_pk: int, event: str) -> int:
    """Notify the relevant security team about a triage-advisory event.

    ``event`` ∈ {``advisory_triage_submitted``, ``advisory_triage_promoted``,
    ``advisory_triage_dismissed``, ``advisory_triage_reassigned``,
    ``advisory_flagged_for_routing``, ``advisory_routing_flag_cleared``,
    ``advisory_reopened``}.
    Body templates carry no raw reporter content (no email/name/details) —
    the link lands recipients in the triage detail page where they decide
    what to read.
    """
    try:
        advisory = Advisory.objects.select_related("project").get(pk=advisory_pk)
    except Advisory.DoesNotExist:
        return 0

    from .recipients import get_pref

    admins_only = event == "advisory_flagged_for_routing"
    recipients = _advisory_triage_recipients(advisory, admins_only=admins_only)
    # Honour the global opt-out. Shadow users carry a default preference
    # (on_triage_event=True), so they are reached unless the member later logs
    # in and opts out — same gating as advisory_created.
    recipients = [u for u in recipients if get_pref(u).on_triage_event]
    subject_map = {
        "advisory_triage_submitted": "[AdvisoryHub] new vulnerability report (triage)",
        "advisory_triage_promoted": "[AdvisoryHub] triage advisory promoted to draft",
        "advisory_triage_dismissed": "[AdvisoryHub] triage advisory dismissed",
        "advisory_triage_reassigned": "[AdvisoryHub] triage advisory reassigned to your project",
        "advisory_flagged_for_routing": "[AdvisoryHub] triage advisory flagged for admin re-routing",
        "advisory_routing_flag_cleared": (
            "[AdvisoryHub] triage advisory routing flag cleared — back in your queue"
        ),
        "advisory_reopened": "[AdvisoryHub] dismissed advisory reopened",
    }
    subject = subject_map.get(event, f"[AdvisoryHub] triage event: {event}")
    context = {
        "advisory": advisory,
        "event": event,
        "url": _advisory_url(advisory),
    }
    sent = 0
    for user in recipients:
        try:
            _send_one(
                recipient=user,
                subject=subject,
                template="advisory_triage_event",
                context=context,
                kind=NotificationKind.TRIAGE,
                advisory=advisory,
            )
            sent += 1
        except Exception:  # pragma: no cover
            log.exception("Failed to send %s triage notification to %s", event, user.email)
    return sent


@shared_task(name="notifications.send_intake_event_email")
def send_intake_event_email(report_id: str, event: str) -> int:
    """Legacy task — kept as a no-op for in-flight Celery jobs.

    The intake report model has been folded into ``advisories.Advisory``
    with a ``triage`` state; new code emits via
    :func:`send_advisory_triage_event_email`. This stub absorbs any
    leftover scheduled jobs from the previous code path without raising
    (e.g. if a worker is still draining a queue across the cutover).
    """
    log.info(
        "send_intake_event_email called as a no-op (legacy): report_id=%s event=%s",
        report_id,
        event,
    )
    return 0


@shared_task(name="notifications.send_invitation_email")
def send_invitation_email(invitation_id: int) -> int:
    # No inbox row is recorded here: invitations are addressed to a bare email
    # that may have no ``User`` row yet, and the inbox is per-``User``. By the
    # time the invitee logs in and gains access they already hold the grant.
    from access.models import PendingInvitation

    try:
        invite = PendingInvitation.objects.select_related("advisory").get(pk=invitation_id)
    except PendingInvitation.DoesNotExist:
        return 0
    if invite.redeemed_at is not None:
        return 0
    try:
        send_mail(
            subject=f"[{invite.advisory.advisory_id}] you're invited to view a security advisory",
            message=render_to_string(
                "notifications/invitation.txt",
                {"invite": invite, "url": _advisory_url(invite.advisory)},
            ),
            html_message=render_to_string(
                "notifications/invitation.html",
                {"invite": invite, "url": _advisory_url(invite.advisory)},
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[invite.email],
        )
        # Invitations create no inbox row, so this access-log entry is their
        # only delivery record. Best-effort — the email already went out.
        try:
            audit_record(
                action=Action.NOTIFICATION_SENT,
                actor=None,
                advisory=invite.advisory,
                metadata={"kind": "invitation", "recipient_email": invite.email},
            )
        except Exception:  # pragma: no cover — audit is best-effort
            log.exception("Failed to audit invitation email to %s", invite.email)
        return 1
    except Exception:  # pragma: no cover
        log.exception("Failed to send invitation email to %s", invite.email)
        return 0
