"""Tests for the personal notification inbox.

Covers delivery persistence (one row per recipient, riding on the existing
comment/mention dedup), INV-AUTH-1 at send and display time, shadow-user
inheritance, the auto-read hook on advisory detail, and the mark-read views.
"""

from __future__ import annotations

import pytest
from django.contrib.auth.models import AnonymousUser
from django.core import mail
from django.urls import reverse

from access.models import Permission as AccessPermission
from access.services import grant_to_user, invite_email, revoke
from accounts.models import CommentLevel, NotificationPreference
from advisories.models import Advisory
from comments import services as comment_services
from notifications.models import Notification, NotificationKind
from notifications.services import unread_count
from notifications.tasks import (
    send_advisory_event_email,
    send_advisory_triage_event_email,
    send_comment_email,
    send_comment_mention_email,
    send_invitation_email,
)


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    settings.DEFAULT_FROM_EMAIL = "AdvisoryHub <bot@example.org>"
    member = make_user(email="m@example.org")
    other = make_user(email="other@example.org")
    project = make_project("p", team_members=[member, other])
    advisory = Advisory.objects.create(project=project, summary="x")
    return {"member": member, "other": other, "project": project, "advisory": advisory}


def _shadow_member(project, email="shadow@eclipse.org"):
    from django.utils import timezone

    from accounts.models import User
    from projects.models import SecurityTeamRosterEntry

    user = User.objects.create_user(email=email, is_provisioned=True)
    SecurityTeamRosterEntry.objects.create(
        project=project,
        eclipse_username=email.split("@", 1)[0],
        email=email,
        user=user,
        last_seen_in_pmi_at=timezone.now(),
    )
    return user


# ---- delivery persistence -------------------------------------------------


@pytest.mark.django_db
def test_lifecycle_send_records_one_row_per_recipient(setup):
    sent = send_advisory_event_email(setup["advisory"].pk, "advisory_published")
    rows = Notification.objects.filter(advisory=setup["advisory"], kind="advisory_published")
    assert sent == 2
    assert rows.count() == 2
    assert {r.recipient_id for r in rows} == {setup["member"].pk, setup["other"].pk}
    assert len(mail.outbox) == 2
    assert all(r.subject for r in rows)
    assert all(r.read_at is None for r in rows)


@pytest.mark.django_db
def test_comment_mention_dedup_and_comment_row(setup, make_user):
    """A mentioned user gets exactly one MENTION row (never also a COMMENT row);
    a separate all-comments watcher gets one COMMENT row."""
    NotificationPreference.objects.update_or_create(
        user=setup["other"], defaults={"comments_level": CommentLevel.ALL}
    )
    author = make_user(email="author@example.org")
    author.groups.add(setup["project"].security_team)
    comment = comment_services.add_comment(setup["advisory"], author=author, body="@m please fix")
    mail.outbox.clear()
    send_comment_email(setup["advisory"].pk, comment.pk)

    member_rows = Notification.objects.filter(recipient=setup["member"], comment_id=comment.pk)
    assert member_rows.count() == 1
    assert member_rows.first().kind == NotificationKind.MENTION

    other_rows = Notification.objects.filter(recipient=setup["other"], comment_id=comment.pk)
    assert other_rows.count() == 1
    assert other_rows.first().kind == NotificationKind.COMMENT


@pytest.mark.django_db
def test_comment_edit_delta_records_only_new_mention(setup, make_user):
    newly = make_user(email="newly@example.org")
    newly.groups.add(setup["project"].security_team)
    comment = comment_services.add_comment(setup["advisory"], author=setup["member"], body="hello")
    mail.outbox.clear()
    send_comment_mention_email(setup["advisory"].pk, comment.pk, [newly.pk], [])
    rows = Notification.objects.filter(comment_id=comment.pk)
    assert rows.count() == 1
    assert rows.first().recipient_id == newly.pk
    assert rows.first().kind == NotificationKind.MENTION


# ---- INV-AUTH-1 at send time ----------------------------------------------


@pytest.mark.django_db
def test_no_row_for_user_without_access(setup, make_user):
    make_user(email="stranger@example.org")
    send_advisory_event_email(setup["advisory"].pk, "advisory_published")
    assert not Notification.objects.filter(recipient__email="stranger@example.org").exists()


@pytest.mark.django_db
def test_revoked_grantee_gets_no_row(setup, make_user):
    grantee = make_user(email="g@example.org")
    grant = grant_to_user(setup["advisory"], grantee, AccessPermission.VIEWER, by=setup["member"])
    revoke(grant, by=setup["member"])
    send_advisory_event_email(setup["advisory"].pk, "advisory_published")
    assert not Notification.objects.filter(recipient=grantee).exists()


# ---- shadow users ---------------------------------------------------------


@pytest.mark.django_db
def test_shadow_user_row_survives_first_login(setup):
    shadow = _shadow_member(setup["project"])
    send_advisory_triage_event_email(setup["advisory"].pk, "advisory_triage_submitted")
    row = Notification.objects.filter(recipient=shadow, kind=NotificationKind.TRIAGE).first()
    assert row is not None
    # First login clears the shadow flag in place — same PK, so the row is kept.
    shadow.is_provisioned = False
    shadow.save(update_fields=["is_provisioned"])
    assert Notification.objects.filter(pk=row.pk, recipient=shadow).exists()
    assert unread_count(shadow) >= 1


# ---- invitations are excluded ---------------------------------------------


@pytest.mark.django_db
def test_invitation_creates_no_notification_rows(setup):
    invite = invite_email(
        setup["advisory"], "invitee@example.org", AccessPermission.VIEWER, by=setup["member"]
    )
    mail.outbox.clear()
    send_invitation_email(invite.pk)
    assert Notification.objects.count() == 0
    assert len(mail.outbox) == 1


# ---- auto-read on advisory detail -----------------------------------------


@pytest.mark.django_db
def test_opening_advisory_marks_its_notifications_read(setup, client):
    client.force_login(setup["member"])
    mine = Notification.objects.create(
        recipient=setup["member"],
        advisory=setup["advisory"],
        kind=NotificationKind.COMMENT,
        subject="here",
    )
    other_adv = Advisory.objects.create(project=setup["project"], summary="y")
    elsewhere = Notification.objects.create(
        recipient=setup["member"],
        advisory=other_adv,
        kind=NotificationKind.COMMENT,
        subject="there",
    )
    resp = client.get(reverse("advisories:detail", args=[setup["advisory"].advisory_id]))
    assert resp.status_code == 200
    mine.refresh_from_db()
    elsewhere.refresh_from_db()
    assert mine.read_at is not None
    assert elsewhere.read_at is None


# ---- mark-read views ------------------------------------------------------


@pytest.mark.django_db
def test_mark_read_only_own(setup, client, make_user):
    stranger = make_user(email="z@example.org")
    foreign = Notification.objects.create(
        recipient=stranger,
        advisory=setup["advisory"],
        kind=NotificationKind.COMMENT,
        subject="not yours",
    )
    client.force_login(setup["member"])
    resp = client.post(reverse("notifications:mark_read", args=[foreign.pk]))
    assert resp.status_code == 404
    foreign.refresh_from_db()
    assert foreign.read_at is None


@pytest.mark.django_db
def test_mark_read_htmx_returns_row_partial(setup, client):
    client.force_login(setup["member"])
    n = Notification.objects.create(
        recipient=setup["member"],
        advisory=setup["advisory"],
        kind=NotificationKind.COMMENT,
        subject="ping",
    )
    resp = client.post(reverse("notifications:mark_read", args=[n.pk]), HTTP_HX_REQUEST="true")
    assert resp.status_code == 200
    assert f'id="notif-{n.pk}"'.encode() in resp.content
    n.refresh_from_db()
    assert n.read_at is not None


@pytest.mark.django_db
def test_mark_all_read(setup, client, make_user):
    client.force_login(setup["member"])
    for subj in ("a", "b"):
        Notification.objects.create(
            recipient=setup["member"],
            advisory=setup["advisory"],
            kind=NotificationKind.COMMENT,
            subject=subj,
        )
    stranger = make_user(email="z@example.org")
    foreign = Notification.objects.create(
        recipient=stranger,
        advisory=setup["advisory"],
        kind=NotificationKind.COMMENT,
        subject="c",
    )
    resp = client.post(reverse("notifications:mark_all_read"))
    assert resp.status_code == 302
    assert unread_count(setup["member"]) == 0
    foreign.refresh_from_db()
    assert foreign.read_at is None


# ---- inbox visibility re-check (INV-AUTH-1 at display) ---------------------


@pytest.mark.django_db
def test_inbox_lists_row_without_link_when_no_longer_visible(setup, client, make_user):
    grantee = make_user(email="g@example.org")
    grant = grant_to_user(setup["advisory"], grantee, AccessPermission.VIEWER, by=setup["member"])
    Notification.objects.create(
        recipient=grantee,
        advisory=setup["advisory"],
        kind=NotificationKind.COMMENT,
        subject="kept-subject",
    )
    revoke(grant, by=setup["member"])
    client.force_login(grantee)
    resp = client.get(reverse("notifications:inbox"))
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "kept-subject" in body  # the row is still shown
    detail_url = reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    assert detail_url not in body  # but it is not a link


# ---- unread-count badge ---------------------------------------------------


@pytest.mark.django_db
def test_unread_badge_rendered_in_nav(setup, client):
    client.force_login(setup["member"])
    Notification.objects.create(
        recipient=setup["member"],
        advisory=setup["advisory"],
        kind=NotificationKind.COMMENT,
        subject="a",
    )
    resp = client.get(reverse("advisories:list"))
    assert resp.status_code == 200
    assert b"notif-unread-badge" in resp.content


def test_unread_count_zero_for_anonymous():
    assert unread_count(AnonymousUser()) == 0
