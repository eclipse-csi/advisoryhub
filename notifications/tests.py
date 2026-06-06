from __future__ import annotations

import pytest
from django.core import mail
from django.urls import reverse

from access.models import Permission as AccessPermission
from access.services import grant_to_user
from accounts.models import CommentLevel, NotificationPreference
from advisories.models import Advisory
from comments import services as comment_services
from notifications import recipients
from notifications.models import AdvisoryNotificationPreference
from notifications.tasks import (
    send_advisory_event_email,
    send_comment_email,
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
    return {"member": member, "other": other, "advisory": advisory, "project": project}


# ---- advisory_created event ----------------------------------------------


@pytest.mark.django_db
def test_advisory_created_only_targets_security_team(setup, make_user):
    """advisory_created fires only for project security team members,
    not grantees or random users."""
    grantee = make_user(email="grantee@example.org")
    grant_to_user(setup["advisory"], grantee, AccessPermission.VIEWER, by=setup["member"])
    stranger = make_user(email="stranger@example.org")

    out = recipients.filter_for_event(setup["advisory"], event="advisory_created")
    emails = {u.email for u in out}
    assert setup["member"].email in emails
    assert setup["other"].email in emails
    assert grantee.email not in emails
    assert stranger.email not in emails


@pytest.mark.django_db
def test_advisory_created_respects_global_pref(setup):
    NotificationPreference.objects.create(user=setup["other"], on_advisory_created=False)
    out = recipients.filter_for_event(setup["advisory"], event="advisory_created")
    emails = {u.email for u in out}
    assert setup["other"].email not in emails
    assert setup["member"].email in emails


@pytest.mark.django_db
def test_advisory_created_ignores_per_advisory_override(setup):
    """Per-advisory prefs don't apply to advisory_created — global only."""
    AdvisoryNotificationPreference.objects.create(
        user=setup["other"],
        advisory=setup["advisory"],
        on_advisory_submitted_for_review=False,
        on_advisory_published=False,
        on_publication_export_status=False,
        comments_level=CommentLevel.MENTIONED,
    )
    out = recipients.filter_for_event(setup["advisory"], event="advisory_created")
    assert setup["other"] in out


# ---- Lifecycle events: per-advisory override -----------------------------


@pytest.mark.django_db
def test_lifecycle_per_advisory_override_silences_one_event(setup):
    """Override for one specific event overrides only that event."""
    AdvisoryNotificationPreference.objects.create(
        user=setup["other"],
        advisory=setup["advisory"],
        on_advisory_published=False,
    )
    out_pub = recipients.filter_for_event(setup["advisory"], event="advisory_published")
    out_sub = recipients.filter_for_event(setup["advisory"], event="advisory_submitted_for_review")
    assert setup["other"] not in out_pub
    assert setup["other"] in out_sub  # not overridden — inherits global True
    assert setup["member"] in out_pub


@pytest.mark.django_db
def test_lifecycle_override_falls_back_to_global_when_null(setup):
    """A null override field defers to the user's global setting."""
    AdvisoryNotificationPreference.objects.create(
        user=setup["other"],
        advisory=setup["advisory"],
        on_advisory_published=None,
    )
    NotificationPreference.objects.create(user=setup["other"], on_advisory_published=False)
    out = recipients.filter_for_event(setup["advisory"], event="advisory_published")
    assert setup["other"] not in out  # global False, no override


@pytest.mark.django_db
def test_lifecycle_override_can_re_enable_when_global_off(setup):
    """Per-advisory True overrides a False global — user opted *in* for this advisory."""
    NotificationPreference.objects.create(user=setup["other"], on_advisory_published=False)
    AdvisoryNotificationPreference.objects.create(
        user=setup["other"],
        advisory=setup["advisory"],
        on_advisory_published=True,
    )
    out = recipients.filter_for_event(setup["advisory"], event="advisory_published")
    assert setup["other"] in out


# ---- Comment / mention ---------------------------------------------------


@pytest.mark.django_db
def test_comment_mentioned_only_skips_unmentioned(setup, make_user):
    user = make_user(email="alice@example.org")
    grant_to_user(setup["advisory"], user, AccessPermission.VIEWER, by=setup["member"])
    NotificationPreference.objects.create(user=user, comments_level=CommentLevel.MENTIONED)
    out = recipients.filter_for_event(setup["advisory"], event="comment", mentioned_user_ids=[])
    assert user not in out


@pytest.mark.django_db
def test_comment_all_delivers_to_everyone_with_access(setup, make_user):
    user = make_user(email="bob@example.org")
    grant_to_user(setup["advisory"], user, AccessPermission.VIEWER, by=setup["member"])
    NotificationPreference.objects.create(user=user, comments_level=CommentLevel.ALL)
    out = recipients.filter_for_event(setup["advisory"], event="comment", mentioned_user_ids=[])
    assert user in out


@pytest.mark.django_db
def test_comment_per_advisory_override_beats_global(setup, make_user):
    user = make_user(email="carol@example.org")
    grant_to_user(setup["advisory"], user, AccessPermission.VIEWER, by=setup["member"])
    NotificationPreference.objects.create(user=user, comments_level=CommentLevel.ALL)
    AdvisoryNotificationPreference.objects.create(
        user=user, advisory=setup["advisory"], comments_level=CommentLevel.MENTIONED
    )
    out = recipients.filter_for_event(setup["advisory"], event="comment", mentioned_user_ids=[])
    assert user not in out


@pytest.mark.django_db
def test_mention_event_delivers_even_at_minimums(setup, make_user):
    """MENTIONED is the floor — mentions always go through even when the
    user has the most-silenced settings on both global and per-advisory."""
    user = make_user(email="dan@example.org")
    grant_to_user(setup["advisory"], user, AccessPermission.VIEWER, by=setup["member"])
    NotificationPreference.objects.create(
        user=user,
        on_advisory_submitted_for_review=False,
        on_advisory_published=False,
        on_publication_export_status=False,
        comments_level=CommentLevel.MENTIONED,
    )
    AdvisoryNotificationPreference.objects.create(
        user=user,
        advisory=setup["advisory"],
        on_advisory_submitted_for_review=False,
        on_advisory_published=False,
        on_publication_export_status=False,
        comments_level=CommentLevel.MENTIONED,
    )
    out = recipients.filter_for_event(
        setup["advisory"], event="mention", mentioned_user_ids=[user.pk]
    )
    assert user in out


@pytest.mark.django_db
def test_mention_event_skips_users_without_access(setup, make_user):
    not_granted = make_user(email="ng@example.org")
    out = recipients.filter_for_event(
        setup["advisory"], event="mention", mentioned_user_ids=[not_granted.pk]
    )
    assert not_granted not in out


@pytest.mark.django_db
def test_internal_comment_drops_viewer_recipients(setup, make_user):
    """Even with ``comments_level=ALL``, a viewer is dropped when the
    comment is internal — they can't see it in the app, so they don't
    get an email about it. The security team member (owner) is kept.
    """
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["member"])
    NotificationPreference.objects.create(user=viewer, comments_level=CommentLevel.ALL)
    # Opt the security-team member in to all comment notifications too,
    # otherwise the default MENTIONED preference makes them fall out of
    # the recipient list for reasons unrelated to the internal flag.
    NotificationPreference.objects.create(user=setup["member"], comments_level=CommentLevel.ALL)

    out_public = recipients.filter_for_event(
        setup["advisory"], event="comment", mentioned_user_ids=[]
    )
    out_internal = recipients.filter_for_event(
        setup["advisory"], event="comment", mentioned_user_ids=[], internal=True
    )
    assert viewer in out_public
    assert viewer not in out_internal
    # Security team (owners) are kept.
    assert setup["member"] in out_internal


@pytest.mark.django_db
def test_mention_in_internal_comment_does_not_email_viewer(setup, make_user):
    """Visibility is the floor — mention does not elevate a viewer past
    the internal cut.
    """
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["member"])
    out = recipients.filter_for_event(
        setup["advisory"],
        event="mention",
        mentioned_user_ids=[viewer.pk],
        internal=True,
    )
    assert viewer not in out


# ---- Tasks ---------------------------------------------------------------


@pytest.mark.django_db
def test_send_advisory_event_email_sends_one_per_recipient(setup):
    mail.outbox.clear()
    sent = send_advisory_event_email(setup["advisory"].pk, "advisory_published")
    assert sent == len(mail.outbox)
    assert sent >= 1


@pytest.mark.django_db
def test_published_advisory_does_not_notify_random_authenticated_users(setup, make_user):
    """Recipients are bounded to admins, security team, and grantees —
    never every authenticated user."""
    from advisories.models import State

    setup["advisory"].state = State.PUBLISHED
    setup["advisory"].save(update_fields=["state"])
    stranger = make_user(email="stranger@example.org")
    out = recipients.filter_for_event(setup["advisory"], event="advisory_published")
    emails = {u.email for u in out}
    assert stranger.email not in emails
    assert setup["member"].email in emails


@pytest.mark.django_db
def test_send_comment_email_dedupes_mentioned_recipients(setup):
    NotificationPreference.objects.create(user=setup["member"], comments_level=CommentLevel.ALL)
    NotificationPreference.objects.create(user=setup["other"], comments_level=CommentLevel.ALL)
    comment = comment_services.add_comment(
        setup["advisory"], author=setup["member"], body="hi @other thanks"
    )
    mail.outbox.clear()
    send_comment_email(setup["advisory"].pk, comment.pk)
    other_addr = setup["other"].email
    received_for_other = [m for m in mail.outbox if other_addr in m.to]
    assert len(received_for_other) == 1
    assert "mention" in received_for_other[0].subject.lower()


@pytest.mark.django_db
def test_revoked_user_does_not_get_notified_even_with_override(setup, make_user):
    revoked = make_user(email="revoked@example.org")
    grant = grant_to_user(setup["advisory"], revoked, AccessPermission.VIEWER, by=setup["member"])
    NotificationPreference.objects.create(user=revoked, comments_level=CommentLevel.ALL)
    AdvisoryNotificationPreference.objects.create(
        user=revoked, advisory=setup["advisory"], comments_level=CommentLevel.ALL
    )
    comment = comment_services.add_comment(
        setup["advisory"], author=setup["member"], body="hi @revoked"
    )
    grant.delete()
    mail.outbox.clear()
    send_comment_email(setup["advisory"].pk, comment.pk)
    assert not any("revoked@example.org" in m.to for m in mail.outbox)


@pytest.mark.django_db
def test_group_mention_emails_visible_members(setup, make_user):
    """@group expands to its members; those with visibility get a mention."""
    from django.contrib.auth.models import Group

    from access.services import grant_to_group

    group = Group.objects.create(name="responders")
    m1 = make_user(email="m1@example.org")
    m2 = make_user(email="m2@example.org")
    m1.groups.add(group)
    m2.groups.add(group)
    grant_to_group(setup["advisory"], group, AccessPermission.VIEWER, by=setup["member"])

    comment = comment_services.add_comment(
        setup["advisory"], author=setup["member"], body="ping @responders please look"
    )
    mail.outbox.clear()
    send_comment_email(setup["advisory"].pk, comment.pk)
    emailed = {addr for m in mail.outbox for addr in m.to}
    assert "m1@example.org" in emailed
    assert "m2@example.org" in emailed


@pytest.mark.django_db
def test_group_mention_skips_member_without_visibility(setup, make_user):
    """Membership alone grants nothing — a group with no access path to the
    advisory does not get its members notified (mention can't elevate)."""
    from django.contrib.auth.models import Group

    group = Group.objects.create(name="randoms")
    outsider = make_user(email="outsider@example.org")
    outsider.groups.add(group)

    comment = comment_services.add_comment(
        setup["advisory"], author=setup["member"], body="ping @randoms"
    )
    mail.outbox.clear()
    send_comment_email(setup["advisory"].pk, comment.pk)
    assert not any("outsider@example.org" in m.to for m in mail.outbox)


@pytest.mark.django_db
def test_send_comment_mention_email_restricts_and_rechecks(setup, make_user):
    """The edit-path task emails only the passed recipient ids, and still
    re-checks ``can_view`` at send time (INV-AUTH-1)."""
    from notifications.tasks import send_comment_mention_email

    alice = make_user(email="alice@example.org")
    revoked = make_user(email="revoked@example.org")
    grant_to_user(setup["advisory"], alice, AccessPermission.VIEWER, by=setup["member"])
    grant = grant_to_user(setup["advisory"], revoked, AccessPermission.VIEWER, by=setup["member"])
    comment = comment_services.add_comment(
        setup["advisory"], author=setup["member"], body="hi @alice @revoked"
    )
    grant.delete()  # revoked loses access between the edit and the send

    mail.outbox.clear()
    sent = send_comment_mention_email(setup["advisory"].pk, comment.pk, [alice.pk, revoked.pk])
    emailed = {addr for m in mail.outbox for addr in m.to}
    assert "alice@example.org" in emailed
    assert "revoked@example.org" not in emailed
    assert sent == 1


@pytest.mark.django_db
def test_send_comment_mention_email_noop_for_empty_recipients(setup):
    from notifications.tasks import send_comment_mention_email

    comment = comment_services.add_comment(
        setup["advisory"], author=setup["member"], body="no mentions here"
    )
    mail.outbox.clear()
    assert send_comment_mention_email(setup["advisory"].pk, comment.pk, []) == 0
    assert mail.outbox == []


@pytest.mark.django_db
def test_send_invitation_email_sends_to_invited_address(setup):
    from access.models import PendingInvitation, Permission

    invite = PendingInvitation.objects.create(
        advisory=setup["advisory"],
        email="invited@example.org",
        permission=Permission.VIEWER,
    )
    mail.outbox.clear()
    sent = send_invitation_email(invite.pk)
    assert sent == 1
    assert mail.outbox[0].to == ["invited@example.org"]


# ---- Notification deliveries land in the access log -----------------------
# Each delivered notification writes one ephemeral AccessLogEntry
# (action=notification.sent), so admins get a single system-wide view of what
# went out. The recipient lives in metadata (the access log has no recipient
# column) and is findable via the metadata search.


@pytest.mark.django_db
def test_lifecycle_send_records_notification_sent_per_recipient(setup):
    from audit.models import AccessLogEntry, Action, AuditLogEntry

    mail.outbox.clear()
    sent = send_advisory_event_email(setup["advisory"].pk, "advisory_published")
    rows = AccessLogEntry.objects.filter(action=Action.NOTIFICATION_SENT)
    assert sent >= 1
    assert rows.count() == sent  # one access-log row per delivered email
    # Ephemeral by design — never the durable ledger.
    assert not AuditLogEntry.objects.filter(action=Action.NOTIFICATION_SENT).exists()
    sample = rows.first()
    assert sample.metadata["kind"] == "advisory_published"
    assert "recipient_email" in sample.metadata
    assert sample.advisory_id == setup["advisory"].pk
    assert sample.actor_id is None  # system delivery (no request in the worker)


@pytest.mark.django_db
def test_comment_send_records_notification_sent_with_comment_id(setup):
    from audit.models import AccessLogEntry, Action

    NotificationPreference.objects.create(user=setup["other"], comments_level=CommentLevel.ALL)
    comment = comment_services.add_comment(
        setup["advisory"], author=setup["member"], body="hi @other"
    )
    mail.outbox.clear()
    sent = send_comment_email(setup["advisory"].pk, comment.pk)
    rows = AccessLogEntry.objects.filter(action=Action.NOTIFICATION_SENT)
    assert sent >= 1
    assert rows.count() == sent
    assert all(r.metadata.get("comment_id") == comment.pk for r in rows)


@pytest.mark.django_db
def test_invitation_send_records_notification_sent(setup):
    from access.models import PendingInvitation, Permission
    from audit.models import AccessLogEntry, Action

    invite = PendingInvitation.objects.create(
        advisory=setup["advisory"],
        email="invited@example.org",
        permission=Permission.VIEWER,
    )
    mail.outbox.clear()
    assert send_invitation_email(invite.pk) == 1
    entry = AccessLogEntry.objects.get(action=Action.NOTIFICATION_SENT, advisory=setup["advisory"])
    assert entry.metadata["kind"] == "invitation"
    assert entry.metadata["recipient_email"] == "invited@example.org"


# ---- Forms ---------------------------------------------------------------


@pytest.mark.django_db
def test_preferences_form_wires_save_feedback(client, setup):
    """The form opts into the shared save-feedback JS: an "Unsaved changes"
    marker (``data-unsaved-indicator``) and the double-submit guard
    (``data-submit-once``). Per the forms guide we no longer disable Save to
    gate state, so the old ``data-dirty-form`` attribute is gone and the Save
    button is never rendered ``disabled`` server-side (no-JS keeps it usable)."""
    client.force_login(setup["member"])
    response = client.get(reverse("notifications:preferences"))
    body = response.content.decode()
    assert "data-submit-once" in body
    assert "data-unsaved-indicator" in body
    assert "Unsaved changes" in body
    assert "advisoryhub-form-dirty.js" in body
    assert "data-dirty-form" not in body
    assert '<button type="submit">Save</button>' in body


@pytest.mark.django_db
def test_preferences_page_renders_help_text_for_every_event(client, setup):
    """Every event toggle on the global page should show its help_text,
    so the layout reads consistently instead of having only one row
    annotated."""
    client.force_login(setup["member"])
    response = client.get(reverse("notifications:preferences"))
    assert response.status_code == 200
    body = response.content.decode()
    for fragment in (
        "submitted for review",
        "published to the public repo",
        "publication export",
        "Mentions are always delivered",
    ):
        assert fragment in body, f"missing help_text fragment: {fragment!r}"


@pytest.mark.django_db
def test_preferences_page_renders_comments_segmented_toggle(client, setup):
    """The two-choice comments_level is rendered as a segmented control
    (radio buttons styled as connected buttons), not a <select>.

    The active-state highlight is driven purely by CSS ``:has(:checked)``
    on the labels — so the test verifies the ``checked`` attribute on
    the right radio, not a server-rendered class. (Using a static class
    leaves the previously-selected option highlighted after a click
    because the DOM class is stale until the form re-renders.)
    """
    NotificationPreference.objects.create(user=setup["member"], comments_level=CommentLevel.ALL)
    client.force_login(setup["member"])
    response = client.get(reverse("notifications:preferences"))
    body = response.content.decode()
    assert 'class="pref-toggle"' in body
    assert 'name="comments_level"' in body
    # Find each radio's full <input> tag and confirm the right one
    # carries the ``checked`` attribute.
    import re

    all_input = re.search(r'<input[^>]*value="all"[^>]*>', body).group(0)
    mentioned_input = re.search(r'<input[^>]*value="mentioned"[^>]*>', body).group(0)
    assert "checked" in all_input
    assert "checked" not in mentioned_input


@pytest.mark.django_db
def test_global_form_rejects_legacy_none_comment_level():
    """The legacy "none" choice is no longer accepted."""
    from notifications.forms import NotificationPreferenceForm

    form = NotificationPreferenceForm(
        data={
            "on_advisory_created": "on",
            "on_advisory_submitted_for_review": "on",
            "on_advisory_published": "on",
            "on_publication_export_status": "on",
            "comments_level": "none",
        }
    )
    assert not form.is_valid()
    assert "comments_level" in form.errors


# ---- Per-advisory preferences view ---------------------------------------


@pytest.mark.django_db
def test_advisory_preferences_panel_get_renders(client, setup):
    """GET returns the panel partial for HTMX lazy-load."""
    client.force_login(setup["member"])
    url = reverse("notifications:advisory_preferences", args=[setup["advisory"].advisory_id])
    response = client.get(url)
    assert response.status_code == 200
    body = response.content.decode()
    assert 'id="advisory-notifications"' in body
    assert 'name="preset"' in body


@pytest.mark.django_db
def test_advisory_preferences_preset_all_writes_full_override(client, setup):
    client.force_login(setup["member"])
    url = reverse("notifications:advisory_preferences", args=[setup["advisory"].advisory_id])
    response = client.post(url, data={"preset": "all"})
    assert response.status_code == 200
    row = AdvisoryNotificationPreference.objects.get(
        user=setup["member"], advisory=setup["advisory"]
    )
    assert row.on_advisory_submitted_for_review is True
    assert row.on_advisory_published is True
    assert row.on_publication_export_status is True
    assert row.comments_level == CommentLevel.ALL


@pytest.mark.django_db
def test_advisory_preferences_preset_digest_writes_key_events(client, setup):
    client.force_login(setup["member"])
    url = reverse("notifications:advisory_preferences", args=[setup["advisory"].advisory_id])
    response = client.post(url, data={"preset": "digest"})
    assert response.status_code == 200
    row = AdvisoryNotificationPreference.objects.get(
        user=setup["member"], advisory=setup["advisory"]
    )
    assert row.on_advisory_submitted_for_review is False
    assert row.on_advisory_published is True
    assert row.on_publication_export_status is True
    assert row.comments_level == CommentLevel.MENTIONED


@pytest.mark.django_db
def test_advisory_preferences_preset_default_deletes_row(client, setup):
    AdvisoryNotificationPreference.objects.create(
        user=setup["member"],
        advisory=setup["advisory"],
        on_advisory_published=False,
        comments_level=CommentLevel.ALL,
    )
    client.force_login(setup["member"])
    url = reverse("notifications:advisory_preferences", args=[setup["advisory"].advisory_id])
    response = client.post(url, data={"preset": "default"})
    assert response.status_code == 200
    assert not AdvisoryNotificationPreference.objects.filter(
        user=setup["member"], advisory=setup["advisory"]
    ).exists()


@pytest.mark.django_db
def test_advisory_preferences_preset_custom_uses_fine_grained_inputs(client, setup):
    client.force_login(setup["member"])
    url = reverse("notifications:advisory_preferences", args=[setup["advisory"].advisory_id])
    response = client.post(
        url,
        data={
            "preset": "custom",
            "on_advisory_submitted_for_review": "off",
            "on_advisory_published": "",
            "on_publication_export_status": "on",
            "comments_level": "",
        },
    )
    assert response.status_code == 200
    row = AdvisoryNotificationPreference.objects.get(
        user=setup["member"], advisory=setup["advisory"]
    )
    assert row.on_advisory_submitted_for_review is False
    assert row.on_advisory_published is None
    assert row.on_publication_export_status is True
    assert row.comments_level == ""


@pytest.mark.django_db
def test_advisory_preferences_view_blocks_user_without_access(client, setup, make_user):
    outsider = make_user(email="outsider@example.org")
    client.force_login(outsider)
    url = reverse("notifications:advisory_preferences", args=[setup["advisory"].advisory_id])
    response = client.post(url, data={"preset": "all"})
    assert response.status_code == 403


@pytest.mark.django_db
def test_advisory_preferences_view_audits_with_advisory(client, setup):
    from audit.models import Action, AuditLogEntry

    client.force_login(setup["member"])
    url = reverse("notifications:advisory_preferences", args=[setup["advisory"].advisory_id])
    client.post(url, data={"preset": "digest"})
    entry = AuditLogEntry.objects.filter(
        action=Action.NOTIFICATION_PREFS_CHANGED, advisory=setup["advisory"]
    ).first()
    assert entry is not None
    assert entry.new_value == {
        "on_advisory_submitted_for_review": False,
        "on_advisory_published": True,
        "on_publication_export_status": True,
        "comments_level": "mentioned",
    }


@pytest.mark.django_db
def test_advisory_preferences_post_custom_with_no_overrides_stays_on_custom(client, setup):
    """Clicking "Custom" from a fresh state (no row, all defaults) must
    leave the panel showing Custom checked — not snap back to Default."""
    client.force_login(setup["member"])
    url = reverse("notifications:advisory_preferences", args=[setup["advisory"].advisory_id])
    response = client.post(url, data={"preset": "custom"})
    assert response.status_code == 200
    body = response.content.decode()
    # The custom fieldset only renders when the active preset is 'custom'.
    assert 'class="notif-custom"' in body
    # Row should NOT exist (no changes to persist), but the UI is sticky on Custom.
    assert not AdvisoryNotificationPreference.objects.filter(
        user=setup["member"], advisory=setup["advisory"]
    ).exists()


@pytest.mark.django_db
def test_detect_preset_round_trip(setup):
    """The preset stored by a 'preset=all' POST must round-trip back to
    'all' when the panel re-renders, so the UI stays sticky."""
    from notifications.forms import AdvisoryNotificationPreferenceForm
    from notifications.services import get_advisory_preference, set_advisory_preference

    for preset in ("all", "digest"):
        form = AdvisoryNotificationPreferenceForm(data={"preset": preset})
        assert form.is_valid()
        set_advisory_preference(setup["member"], setup["advisory"], **form.materialize())
        row = get_advisory_preference(setup["member"], setup["advisory"])
        assert AdvisoryNotificationPreferenceForm.detect_preset(row) == preset


# ---- Shadow roster members (notification reach, no access) ----------------
# A shadow user is a pre-provisioned, never-logged-in security-team member
# (projects.SecurityTeamRosterEntry + User.is_provisioned). They receive the
# default notification set of a team member but hold no in-app access. See
# INV-OIDC-5 / INV-NOTIFY-x.


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


@pytest.mark.django_db
def test_shadow_reached_by_team_mention(setup):
    shadow = _shadow_member(setup["project"])
    # The project's security team group is "p-security" (make_project fixture).
    comment = comment_services.add_comment(
        setup["advisory"], author=setup["member"], body="ping @p-security please"
    )
    mail.outbox.clear()
    send_comment_email(setup["advisory"].pk, comment.pk)
    emailed = {addr for m in mail.outbox for addr in m.to}
    assert shadow.email in emailed


@pytest.mark.django_db
def test_shadow_reached_by_advisory_created(setup):
    shadow = _shadow_member(setup["project"])
    out = recipients.filter_for_event(setup["advisory"], event="advisory_created")
    assert shadow.pk in {u.pk for u in out}


@pytest.mark.django_db
def test_shadow_reached_by_lifecycle_event(setup):
    shadow = _shadow_member(setup["project"])
    out = recipients.filter_for_event(setup["advisory"], event="advisory_published")
    assert shadow.pk in {u.pk for u in out}


@pytest.mark.django_db
def test_shadow_not_reached_by_plain_comment(setup):
    """Default comments_level is MENTIONED → a shadow does not get every
    comment, only mentions (same as a default-pref logged-in member)."""
    shadow = _shadow_member(setup["project"])
    comment = comment_services.add_comment(
        setup["advisory"], author=setup["member"], body="just a plain comment, nobody mentioned"
    )
    mail.outbox.clear()
    send_comment_email(setup["advisory"].pk, comment.pk)
    emailed = {addr for m in mail.outbox for addr in m.to}
    assert shadow.email not in emailed


@pytest.mark.django_db
def test_shadow_not_reached_by_internal_comment_mention(setup):
    """The internal-comment floor drops shadows even when the team is @-mentioned."""
    shadow = _shadow_member(setup["project"])
    comment = comment_services.add_comment(
        setup["advisory"],
        author=setup["member"],
        body="internal: @p-security look",
        internal=True,
    )
    mail.outbox.clear()
    send_comment_email(setup["advisory"].pk, comment.pk)
    emailed = {addr for m in mail.outbox for addr in m.to}
    assert shadow.email not in emailed


@pytest.mark.django_db
def test_shadow_on_other_project_not_reached(setup, make_project):
    other_project = make_project("q")
    shadow = _shadow_member(other_project, email="elsewhere@eclipse.org")
    # advisory belongs to setup["project"], not other_project.
    out = recipients.filter_for_event(setup["advisory"], event="advisory_created")
    assert shadow.pk not in {u.pk for u in out}


@pytest.mark.django_db
def test_soft_removed_shadow_not_reached(setup):
    from django.utils import timezone

    from projects.models import SecurityTeamRosterEntry

    shadow = _shadow_member(setup["project"])
    SecurityTeamRosterEntry.objects.filter(user=shadow).update(soft_removed_at=timezone.now())
    out = recipients.filter_for_event(setup["advisory"], event="advisory_published")
    assert shadow.pk not in {u.pk for u in out}


@pytest.mark.django_db
def test_no_double_send_after_shadow_logs_in(setup):
    """A formerly-shadow user who has logged in (is_provisioned=False, in the
    team group) is a normal candidate and is not double-counted."""
    from django.utils import timezone

    from accounts.models import User
    from projects.models import SecurityTeamRosterEntry

    user = User.objects.create_user(email="grown@eclipse.org", is_provisioned=False)
    user.groups.add(setup["project"].security_team)  # real membership via claim
    SecurityTeamRosterEntry.objects.create(
        project=setup["project"],
        eclipse_username="grown",
        email="grown@eclipse.org",
        user=user,
        last_seen_in_pmi_at=timezone.now(),
    )
    out = recipients.filter_for_event(setup["advisory"], event="advisory_published")
    pks = [u.pk for u in out]
    assert pks.count(user.pk) == 1


# ---- Triage events reach shadows + global on_triage_event opt-out ---------


@pytest.mark.django_db
def test_shadow_reached_by_triage_event(setup):
    from notifications.tasks import send_advisory_triage_event_email

    shadow = _shadow_member(setup["project"])
    mail.outbox.clear()
    send_advisory_triage_event_email(setup["advisory"].pk, "advisory_triage_submitted")
    emailed = {addr for m in mail.outbox for addr in m.to}
    assert shadow.email in emailed


@pytest.mark.django_db
def test_triage_event_respects_global_opt_out(setup):
    from notifications.tasks import send_advisory_triage_event_email

    # member opts out; other keeps the default (on).
    NotificationPreference.objects.create(user=setup["member"], on_triage_event=False)
    mail.outbox.clear()
    send_advisory_triage_event_email(setup["advisory"].pk, "advisory_triage_promoted")
    emailed = {addr for m in mail.outbox for addr in m.to}
    assert setup["member"].email not in emailed
    assert setup["other"].email in emailed


@pytest.mark.django_db
def test_flagged_for_routing_excludes_project_shadows(setup):
    """The admins-only routing-flag event never reaches project shadows."""
    from notifications.tasks import send_advisory_triage_event_email

    shadow = _shadow_member(setup["project"])
    mail.outbox.clear()
    send_advisory_triage_event_email(setup["advisory"].pk, "advisory_flagged_for_routing")
    emailed = {addr for m in mail.outbox for addr in m.to}
    assert shadow.email not in emailed


@pytest.mark.django_db
def test_soft_removed_shadow_not_reached_by_triage_event(setup):
    from django.utils import timezone

    from notifications.tasks import send_advisory_triage_event_email
    from projects.models import SecurityTeamRosterEntry

    shadow = _shadow_member(setup["project"])
    SecurityTeamRosterEntry.objects.filter(user=shadow).update(soft_removed_at=timezone.now())
    mail.outbox.clear()
    send_advisory_triage_event_email(setup["advisory"].pk, "advisory_triage_submitted")
    emailed = {addr for m in mail.outbox for addr in m.to}
    assert shadow.email not in emailed
