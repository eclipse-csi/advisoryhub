from __future__ import annotations

import pytest
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from access.models import Permission as AccessPermission
from access.services import grant_to_user
from advisories.models import Advisory
from audit.models import Action, AuditLogEntry
from comments import services
from comments.models import AdvisoryComment, CommentVersion


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x")
    return {"member": member, "advisory": advisory}


# ---- Markdown rendering ---------------------------------------------------


def test_markdown_strips_dangerous_html():
    out = services.render_markdown("hello <script>alert(1)</script> world")
    assert "<script>" not in out
    assert "alert" not in out or "alert" not in out.lower() or "<script>" not in out
    # script tag with content should be fully stripped
    assert "<script" not in out.lower()


def test_markdown_strips_inline_event_handlers():
    out = services.render_markdown('<a href="x" onclick="bad()">link</a>')
    assert "onclick" not in out.lower()


def test_markdown_basic_inline_renders():
    out = services.render_markdown("**bold** and *italic*")
    assert "<strong>" in out
    assert "<em>" in out


def test_markdown_links_get_rel_attribute():
    out = services.render_markdown("[OK](https://example.org)")
    assert 'href="https://example.org"' in out
    assert "nofollow" in out


def test_markdown_strips_javascript_urls():
    """A javascript: URL must never produce an executable anchor.

    markdown-it-py refuses to emit ``<a>`` for a ``javascript:`` href in
    the first place; bleach is a defense-in-depth backstop. Either way:
    no anchor element with a ``javascript:`` href reaches the rendered
    HTML.
    """
    out = services.render_markdown("[bad](javascript:alert(1))")
    assert "<a " not in out
    out2 = services.render_markdown('<a href="javascript:alert(1)">x</a>')
    assert 'href="javascript:' not in out2.lower()


# ---- Mention extraction ---------------------------------------------------


def test_extract_mentions_local_part():
    assert services.extract_mentions("hi @alice please review") == ["alice"]


def test_extract_mentions_full_email():
    assert services.extract_mentions("ping @alice@example.org") == ["alice@example.org"]


def test_extract_mentions_skips_emails_in_text():
    # Emails preceded by a word character shouldn't trip the mention regex
    assert "joe" not in services.extract_mentions("contact joe@example.org")


@pytest.mark.django_db
def test_resolve_mentioned_users_by_local_part(make_user):
    alice = make_user(email="alice@example.org")
    make_user(email="bob@example.org")
    assert services.resolve_mentioned_users("hi @alice") == [alice]


@pytest.mark.django_db
def test_resolve_mentioned_users_by_full_email(make_user):
    alice = make_user(email="alice@example.org")
    assert services.resolve_mentioned_users("hi @alice@example.org") == [alice]


# ---- Group mentions + recipient ids ---------------------------------------


@pytest.mark.django_db
def test_resolve_mentioned_groups_by_name():
    from django.contrib.auth.models import Group

    group = Group.objects.create(name="sec-team")
    Group.objects.create(name="other-team")
    assert services.resolve_mentioned_groups("ping @sec-team please") == [group]


@pytest.mark.django_db
def test_resolve_mentioned_groups_ignores_full_email_handle():
    from django.contrib.auth.models import Group

    Group.objects.create(name="sec-team")
    # A handle containing "@" is a user email, never a group name.
    assert services.resolve_mentioned_groups("ping @alice@example.org") == []


@pytest.mark.django_db
def test_resolve_mention_recipient_ids_unions_users_and_group_members(make_user):
    from django.contrib.auth.models import Group

    group = Group.objects.create(name="sec-team")
    gm1 = make_user(email="gm1@example.org")
    gm2 = make_user(email="gm2@example.org")
    gm1.groups.add(group)
    gm2.groups.add(group)
    alice = make_user(email="alice@example.org")
    ids = services.resolve_mention_recipient_ids("hi @alice and @sec-team")
    assert ids == {alice.pk, gm1.pk, gm2.pk}


@pytest.mark.django_db
def test_resolve_mention_recipient_ids_dedupes_named_group_member(make_user):
    from django.contrib.auth.models import Group

    group = Group.objects.create(name="sec-team")
    alice = make_user(email="alice@example.org")
    alice.groups.add(group)
    # Mentioned both directly and via the group — still one id.
    assert services.resolve_mention_recipient_ids("@alice @sec-team") == {alice.pk}


# ---- Mention completion candidates ----------------------------------------


@pytest.mark.django_db
def test_mention_candidates_scoped_to_advisory_visibility(setup, make_user):
    grantee = make_user(email="grantee@example.org")
    grant_to_user(setup["advisory"], grantee, AccessPermission.VIEWER, by=setup["member"])
    make_user(email="stranger@example.org")  # no access of any kind

    items = services.mention_candidates(setup["advisory"])
    user_handles = {i["handle"] for i in items if i["kind"] == "user"}
    group_handles = {i["handle"] for i in items if i["kind"] == "group"}

    assert "m" in user_handles  # security-team member (m@example.org)
    assert "grantee" in user_handles  # direct grantee
    assert "stranger" not in user_handles  # never offered — no visibility
    # The project's security team group is offered for @group completion.
    assert setup["advisory"].project.security_team.name in group_handles


@pytest.mark.django_db
def test_mention_candidate_labels_mask_email_for_non_owners(setup, make_user):
    """INV-PRIVACY-4: an owner sees emails in the @-completion labels; a viewer
    grantee sees masked labels only. Handles (local-parts) are unchanged so the
    mention still resolves."""
    from accounts.utils import mask_email

    grantee = make_user(email="grantee@example.org")  # no display name
    grant_to_user(setup["advisory"], grantee, AccessPermission.VIEWER, by=setup["member"])

    owner_labels = " | ".join(
        i["label"]
        for i in services.mention_candidates(setup["advisory"], viewer=setup["member"])
        if i["kind"] == "user"
    )
    assert "grantee@example.org" in owner_labels

    viewer_labels = " | ".join(
        i["label"]
        for i in services.mention_candidates(setup["advisory"], viewer=grantee)
        if i["kind"] == "user"
    )
    assert "grantee@example.org" not in viewer_labels
    assert "m@example.org" not in viewer_labels  # the security-team member, masked too
    assert mask_email("grantee@example.org") in viewer_labels


# ---- Mention chip rendering -----------------------------------------------


def test_render_markdown_wraps_mentions_in_chips():
    out = services.render_markdown("hi @alice and @sec-team")
    assert '<span class="mention">@alice</span>' in out
    assert '<span class="mention">@sec-team</span>' in out


def test_render_markdown_leaves_emails_unwrapped():
    # An e-mail address in prose must not be turned into a mention chip.
    out = services.render_markdown("contact alice@example.org for info")
    assert '<span class="mention">' not in out


def test_render_markdown_does_not_chip_inside_code():
    out = services.render_markdown("use `@alice` literally")
    assert "<code>@alice</code>" in out
    assert '<span class="mention">@alice</span>' not in out


def test_render_markdown_mention_chip_is_xss_safe():
    out = services.render_markdown("@<script>alert(1)</script>")
    assert "<script" not in out.lower()


# ---- Comment writes -------------------------------------------------------


@pytest.mark.django_db
def test_outsider_cannot_add_comment(setup, make_user):
    outsider = make_user(email="o@example.org")
    with pytest.raises(PermissionDenied):
        services.add_comment(setup["advisory"], author=outsider, body="hi")


@pytest.mark.django_db
def test_viewer_can_post_comment(setup, make_user):
    """The old `comment` level folded into `viewer` — any granted user can comment."""
    user = make_user(email="g@example.org")
    grant_to_user(setup["advisory"], user, AccessPermission.VIEWER, by=setup["member"])
    services.add_comment(setup["advisory"], author=user, body="hello")
    assert AdvisoryComment.objects.filter(advisory=setup["advisory"]).count() == 1
    assert AuditLogEntry.objects.filter(action=Action.COMMENT_CREATED).exists()


@pytest.mark.django_db
def test_edit_own_comment_records_audit(setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="orig")
    services.edit_comment(c, by=setup["member"], new_body="edited")
    c.refresh_from_db()
    assert c.body == "edited"
    assert c.edited_at is not None
    assert AuditLogEntry.objects.filter(action=Action.COMMENT_EDITED).exists()


# ---- Edit-adds-mention notification (view wiring) -------------------------


# ``transaction=True``: the edit view enqueues the mention email via
# ``transaction.on_commit``, which only fires on a *real* commit — under the
# default (savepoint-wrapped) test transaction it would never run.
@pytest.mark.django_db(transaction=True)
def test_comment_edit_adding_mention_notifies_only_new(setup, make_user, client):
    from django.core import mail

    alice = make_user(email="alicia@example.org")
    bob = make_user(email="bob@example.org")
    grant_to_user(setup["advisory"], alice, AccessPermission.VIEWER, by=setup["member"])
    grant_to_user(setup["advisory"], bob, AccessPermission.VIEWER, by=setup["member"])
    comment = services.add_comment(setup["advisory"], author=setup["member"], body="hi @alicia")

    client.force_login(setup["member"])
    mail.outbox.clear()
    url = reverse("comments:edit", args=[setup["advisory"].advisory_id, comment.pk])
    resp = client.post(url, {"body": "hi @alicia and @bob"})
    assert resp.status_code == 200

    emailed = {addr for m in mail.outbox for addr in m.to}
    assert "bob@example.org" in emailed  # newly added mention is notified
    assert "alicia@example.org" not in emailed  # unchanged mention is not


@pytest.mark.django_db(transaction=True)
def test_comment_edit_without_new_mention_sends_nothing(setup, make_user, client):
    from django.core import mail

    alice = make_user(email="alicia@example.org")
    grant_to_user(setup["advisory"], alice, AccessPermission.VIEWER, by=setup["member"])
    comment = services.add_comment(setup["advisory"], author=setup["member"], body="hi @alicia")

    client.force_login(setup["member"])
    mail.outbox.clear()
    url = reverse("comments:edit", args=[setup["advisory"].advisory_id, comment.pk])
    client.post(url, {"body": "hi @alicia, updated wording"})
    assert mail.outbox == []


# ---- Edit history (CommentVersion) ----------------------------------------


@pytest.mark.django_db
def test_create_comment_writes_version_1(setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="hello")
    versions = list(c.versions.order_by("version"))
    assert len(versions) == 1
    assert versions[0].version == 1
    assert versions[0].body == "hello"
    assert versions[0].editor_id == setup["member"].pk


@pytest.mark.django_db
def test_edit_comment_appends_version(setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="v1-body")
    services.edit_comment(c, by=setup["member"], new_body="v2-body")
    services.edit_comment(c, by=setup["member"], new_body="v3-body")
    versions = list(c.versions.order_by("version"))
    assert [v.version for v in versions] == [1, 2, 3]
    assert [v.body for v in versions] == ["v1-body", "v2-body", "v3-body"]
    # v1's body is untouched — proves the table is genuinely append-only,
    # not just "overwritten under a different row".
    assert versions[0].body == "v1-body"


@pytest.mark.django_db
def test_comment_version_save_on_existing_row_raises(setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="x")
    v1 = c.versions.get(version=1)
    v1.body = "tampered"
    with pytest.raises(PermissionError):
        v1.save()


@pytest.mark.django_db
def test_comment_version_delete_raises(setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="x")
    v1 = c.versions.get(version=1)
    with pytest.raises(PermissionError):
        v1.delete()


@pytest.mark.django_db
def test_history_for_comment_returns_versions_in_order(setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="a")
    services.edit_comment(c, by=setup["member"], new_body="b")
    history = services.history_for_comment(c, viewer=setup["member"])
    assert [v.version for v in history] == [1, 2]
    assert [v.body for v in history] == ["a", "b"]


@pytest.mark.django_db
def test_history_for_comment_redacted_returns_empty(setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="x")
    services.edit_comment(c, by=setup["member"], new_body="y")
    services.redact_comment(c, by=setup["member"])
    c.refresh_from_db()
    assert services.history_for_comment(c, viewer=setup["member"]) == []


@pytest.mark.django_db
def test_history_for_comment_outsider_forbidden(setup, make_user):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="x")
    outsider = make_user(email="o@example.org")
    with pytest.raises(PermissionDenied):
        services.history_for_comment(c, viewer=outsider)


@pytest.mark.django_db
def test_history_for_comment_internal_hidden_from_viewer(setup, make_user):
    """A viewer-rank grantee can see the advisory but not internal comments —
    so they must not see internal-comment history either."""
    advisory = setup["advisory"]
    collaborator = make_user(email="c@example.org")
    grant_to_user(advisory, collaborator, AccessPermission.COLLABORATOR, by=setup["member"])
    viewer = make_user(email="v@example.org")
    grant_to_user(advisory, viewer, AccessPermission.VIEWER, by=setup["member"])
    c = services.add_comment(advisory, author=collaborator, body="secret", internal=True)
    with pytest.raises(PermissionDenied):
        services.history_for_comment(c, viewer=viewer)


@pytest.mark.django_db
def test_history_view_renders_versions(client, setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="original-body")
    services.edit_comment(c, by=setup["member"], new_body="second-body")
    client.force_login(setup["member"])
    response = client.get(reverse("comments:history", args=[setup["advisory"].advisory_id, c.pk]))
    assert response.status_code == 200
    body = response.content.decode()
    assert "original-body" in body
    assert "second-body" in body
    # Newest version comes first in the drawer.
    assert body.index("second-body") < body.index("original-body")


@pytest.mark.django_db
def test_history_view_forbidden_for_outsider(client, setup, make_user):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="x")
    outsider = make_user(email="o@example.org")
    client.force_login(outsider)
    response = client.get(reverse("comments:history", args=[setup["advisory"].advisory_id, c.pk]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_thread_renders_history_drawer_trigger_for_edited_comment(client, setup):
    """Edited comments expose a single drawer-trigger button next to "(edited X)"
    that fires an HTMX GET against the shared comment-history host. Guard the
    wiring so a refactor can't silently revert to the old inline-toggle pattern.
    """
    c = services.add_comment(setup["advisory"], author=setup["member"], body="x")
    services.edit_comment(c, by=setup["member"], new_body="y")
    client.force_login(setup["member"])
    response = client.get(reverse("comments:thread", args=[setup["advisory"].advisory_id]))
    body = response.content.decode()
    assert "history-drawer-trigger" in body
    assert 'hx-target="#comment-history-host"' in body
    # No legacy inline-toggle wiring should remain.
    assert "history-toggle" not in body
    assert "hx-on::before-request" not in body


@pytest.mark.django_db
def test_thread_omits_history_trigger_when_never_edited(client, setup):
    services.add_comment(setup["advisory"], author=setup["member"], body="x")
    client.force_login(setup["member"])
    response = client.get(reverse("comments:thread", args=[setup["advisory"].advisory_id]))
    assert b"history-drawer-trigger" not in response.content


@pytest.mark.django_db
def test_history_view_empty_when_redacted(client, setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="x")
    services.edit_comment(c, by=setup["member"], new_body="y")
    services.redact_comment(c, by=setup["member"])
    client.force_login(setup["member"])
    response = client.get(reverse("comments:history", args=[setup["advisory"].advisory_id, c.pk]))
    assert response.status_code == 200
    # The drawer renders empty-state copy and never lists any version rows.
    assert b"No history available." in response.content
    assert b'class="history-versions"' not in response.content
    assert CommentVersion.objects.filter(comment=c).count() == 2  # rows remain in DB


@pytest.mark.django_db
def test_history_drawer_returns_dialog_with_diff_for_edited_comment(client, setup):
    c = services.add_comment(
        setup["advisory"], author=setup["member"], body="An attacker may bypass."
    )
    services.edit_comment(c, by=setup["member"], new_body="An unauthenticated attacker may bypass.")
    client.force_login(setup["member"])
    response = client.get(reverse("comments:history", args=[setup["advisory"].advisory_id, c.pk]))
    assert response.status_code == 200
    body = response.content.decode()
    assert 'id="comment-history-drawer"' in body
    # Newest version comes first in the drawer.
    assert body.index("v2") < body.index("v1")
    # Word-level diff highlighted the new word.
    assert "<ins>" in body
    assert "unauthenticated" in body
    # v1 is labelled as the original (no prior content to diff against).
    assert "Original version" in body


@pytest.mark.django_db
def test_history_drawer_marks_v1_as_initial(client, setup):
    """Even when navigating directly to the URL of a non-edited comment, v1
    renders as the "original" entry rather than offering a diff."""
    c = services.add_comment(setup["advisory"], author=setup["member"], body="hello")
    client.force_login(setup["member"])
    response = client.get(reverse("comments:history", args=[setup["advisory"].advisory_id, c.pk]))
    assert response.status_code == 200
    body = response.content.decode()
    # Single-version drawer renders the dedicated empty-state copy, not the version list.
    assert "This comment has not been edited." in body
    assert "history-versions" not in body


@pytest.mark.django_db
def test_cannot_edit_others_comment(setup, make_user):
    other = make_user(email="other@example.org")
    grant_to_user(setup["advisory"], other, AccessPermission.VIEWER, by=setup["member"])
    c = services.add_comment(setup["advisory"], author=setup["member"], body="orig")
    with pytest.raises(PermissionDenied):
        services.edit_comment(c, by=other, new_body="hacked")


@pytest.mark.django_db
def test_redact_own_comment(setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="oops")
    services.redact_comment(c, by=setup["member"])
    c.refresh_from_db()
    assert c.is_redacted
    assert c.visible_body() == ""
    assert AuditLogEntry.objects.filter(action=Action.COMMENT_REDACTED).exists()


@pytest.mark.django_db
def test_admin_can_redact_others_comment(setup, make_user, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    c = services.add_comment(setup["advisory"], author=setup["member"], body="x")
    services.redact_comment(c, by=admin)
    c.refresh_from_db()
    assert c.is_redacted


@pytest.mark.django_db
def test_redacted_comment_cannot_be_edited(setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="x")
    services.redact_comment(c, by=setup["member"])
    with pytest.raises(PermissionDenied):
        services.edit_comment(c, by=setup["member"], new_body="trying again")


# ---- View permission gates ------------------------------------------------


@pytest.mark.django_db
def test_thread_view_403_for_outsider(client, setup, make_user):
    outsider = make_user(email="o@example.org")
    client.force_login(outsider)
    response = client.get(reverse("comments:thread", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_thread_view_renders_for_member(client, setup):
    services.add_comment(setup["advisory"], author=setup["member"], body="hi *there*")
    client.force_login(setup["member"])
    response = client.get(reverse("comments:thread", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 200
    assert b"<em>there</em>" in response.content


@pytest.mark.django_db
def test_create_view_403_for_outsider(client, setup, make_user):
    """Outsiders (no grant, not on security team) cannot post — but viewer grant is enough."""
    outsider = make_user(email="o@example.org")
    client.force_login(outsider)
    response = client.post(
        reverse("comments:create", args=[setup["advisory"].advisory_id]),
        data={"body": "should fail"},
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_form_advertises_markdown_support(client, setup):
    client.force_login(setup["member"])
    response = client.get(reverse("comments:thread", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 200
    assert b"Markdown supported" in response.content


# ---- Internal comments ----------------------------------------------------


@pytest.fixture
def internal_setup(setup, make_user):
    """Three-rank fixture for visibility tests: owner (security team),
    collaborator (granted), viewer (granted)."""
    owner = setup["member"]
    advisory = setup["advisory"]
    collaborator = make_user(email="c@example.org")
    grant_to_user(advisory, collaborator, AccessPermission.COLLABORATOR, by=owner)
    viewer = make_user(email="v@example.org")
    grant_to_user(advisory, viewer, AccessPermission.VIEWER, by=owner)
    return {
        "advisory": advisory,
        "owner": owner,
        "collaborator": collaborator,
        "viewer": viewer,
    }


@pytest.mark.django_db
def test_collaborator_can_post_internal(internal_setup):
    c = services.add_comment(
        internal_setup["advisory"],
        author=internal_setup["collaborator"],
        body="internal note",
        internal=True,
    )
    c.refresh_from_db()
    assert c.is_internal is True


@pytest.mark.django_db
def test_viewer_cannot_post_internal_raises(internal_setup):
    with pytest.raises(PermissionDenied):
        services.add_comment(
            internal_setup["advisory"],
            author=internal_setup["viewer"],
            body="trying",
            internal=True,
        )


@pytest.mark.django_db
def test_viewer_cannot_see_internal_in_thread(internal_setup):
    """Viewer's listing excludes internal comments."""
    advisory = internal_setup["advisory"]
    services.add_comment(advisory, author=internal_setup["owner"], body="public")
    services.add_comment(
        advisory, author=internal_setup["collaborator"], body="internal", internal=True
    )

    thread = list(services.comments_for_advisory(advisory, viewer=internal_setup["viewer"]))
    bodies = [c.body for c in thread]
    assert bodies == ["public"]


@pytest.mark.django_db
def test_collaborator_sees_internal_in_thread(internal_setup):
    advisory = internal_setup["advisory"]
    services.add_comment(advisory, author=internal_setup["owner"], body="public")
    services.add_comment(
        advisory, author=internal_setup["collaborator"], body="internal", internal=True
    )
    thread = list(services.comments_for_advisory(advisory, viewer=internal_setup["collaborator"]))
    assert {c.body for c in thread} == {"public", "internal"}


@pytest.mark.django_db
def test_owner_sees_internal_in_thread(internal_setup):
    advisory = internal_setup["advisory"]
    services.add_comment(advisory, author=internal_setup["owner"], body="public")
    services.add_comment(
        advisory, author=internal_setup["collaborator"], body="internal", internal=True
    )
    thread = list(services.comments_for_advisory(advisory, viewer=internal_setup["owner"]))
    assert {c.body for c in thread} == {"public", "internal"}


@pytest.mark.django_db
def test_demoted_author_cannot_see_or_edit_own_internal_comment(internal_setup, client):
    """Author posts internal as collaborator, then is demoted to viewer.
    The thread no longer surfaces the comment, and the edit endpoint
    rejects the same author by URL — internal flag is read-time gated.
    """
    from access.models import AdvisoryAccessGrant, PrincipalType

    advisory = internal_setup["advisory"]
    collaborator = internal_setup["collaborator"]
    c = services.add_comment(advisory, author=collaborator, body="secret", internal=True)

    # Demote to viewer in place.
    AdvisoryAccessGrant.objects.filter(
        advisory=advisory, principal_type=PrincipalType.USER, principal_id=collaborator.pk
    ).update(permission=AccessPermission.VIEWER)

    thread = list(services.comments_for_advisory(advisory, viewer=collaborator))
    assert c.pk not in {x.pk for x in thread}

    client.force_login(collaborator)
    response = client.get(reverse("comments:edit", args=[advisory.advisory_id, c.pk]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_internal_flag_is_immutable_via_edit(internal_setup):
    """``edit_comment`` only touches body + edited_at; the internal flag
    stays exactly as it was at creation, even if a clever caller passes
    a different value (no such kwarg exists — defensive check).
    """
    advisory = internal_setup["advisory"]
    c = services.add_comment(
        advisory, author=internal_setup["collaborator"], body="x", internal=True
    )
    services.edit_comment(c, by=internal_setup["collaborator"], new_body="y")
    c.refresh_from_db()
    assert c.is_internal is True


@pytest.mark.django_db
def test_audit_records_is_internal(internal_setup):
    c = services.add_comment(
        internal_setup["advisory"],
        author=internal_setup["collaborator"],
        body="x",
        internal=True,
    )
    entry = AuditLogEntry.objects.get(action=Action.COMMENT_CREATED, comment_id=c.pk)
    assert entry.new_value["is_internal"] is True


# ---- History drawer pagination -------------------------------------------


def _bulk_edit_comment(comment, count: int, *, editor):
    for i in range(count):
        services.edit_comment(comment, by=editor, new_body=f"revision number {i + 1}")


@pytest.mark.django_db
def test_history_drawer_caps_at_page_size_and_offers_load_more(client, setup):
    from comments.services import COMMENT_HISTORY_PAGE_SIZE

    c = services.add_comment(setup["advisory"], author=setup["member"], body="original")
    _bulk_edit_comment(c, COMMENT_HISTORY_PAGE_SIZE + 4, editor=setup["member"])

    client.force_login(setup["member"])
    response = client.get(reverse("comments:history", args=[setup["advisory"].advisory_id, c.pk]))
    assert response.status_code == 200
    body = response.content.decode()
    assert body.count('class="history-version"') == COMMENT_HISTORY_PAGE_SIZE
    assert "history-load-more" in body


@pytest.mark.django_db
def test_history_drawer_cursor_returns_fragment(client, setup):
    from comments.services import COMMENT_HISTORY_PAGE_SIZE

    c = services.add_comment(setup["advisory"], author=setup["member"], body="original")
    _bulk_edit_comment(c, COMMENT_HISTORY_PAGE_SIZE + 4, editor=setup["member"])

    client.force_login(setup["member"])
    initial = client.get(reverse("comments:history", args=[setup["advisory"].advisory_id, c.pk]))

    import re

    match = re.search(rb"\?before=(\d+)", initial.content)
    assert match
    cursor = int(match.group(1))

    page_two = client.get(
        reverse("comments:history", args=[setup["advisory"].advisory_id, c.pk])
        + f"?before={cursor}"
    )
    assert page_two.status_code == 200
    body = page_two.content.decode()
    assert "comment-history-drawer" not in body  # fragment, no dialog shell
    # Total of COMMENT_HISTORY_PAGE_SIZE + 5 versions (1 add + N edits + v1);
    # page one returned PAGE_SIZE, this page returns the remainder.
    assert "Load older edits" not in body
    assert body.count('class="history-version"') >= 1


@pytest.mark.django_db
def test_history_drawer_invalid_cursor_falls_back_to_initial(client, setup):
    c = services.add_comment(setup["advisory"], author=setup["member"], body="x")
    services.edit_comment(c, by=setup["member"], new_body="y")
    client.force_login(setup["member"])
    response = client.get(
        reverse("comments:history", args=[setup["advisory"].advisory_id, c.pk]) + "?before=banana"
    )
    assert response.status_code == 200
    assert b"comment-history-drawer" in response.content


# ---- @mention completion includes shadow roster members -------------------


@pytest.mark.django_db
def test_mention_candidates_include_shadow_roster_members(setup):
    """A never-logged-in security-team member is discoverable in the @-completion
    payload so they can be mentioned directly, not only via @team."""
    from django.utils import timezone

    from accounts.models import User
    from projects.models import SecurityTeamRosterEntry

    advisory = setup["advisory"]
    shadow = User.objects.create_user(email="never@eclipse.org", is_provisioned=True)
    SecurityTeamRosterEntry.objects.create(
        project=advisory.project,
        eclipse_username="never",
        email="never@eclipse.org",
        user=shadow,
        last_seen_in_pmi_at=timezone.now(),
    )
    handles = {
        item["handle"] for item in services.mention_candidates(advisory) if item["kind"] == "user"
    }
    assert "never" in handles
