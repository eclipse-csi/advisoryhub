"""Tests for the per-advisory unified timeline."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from access.models import Permission as AccessPermission
from access.services import grant_to_user
from advisories import timeline as tl
from advisories.models import Advisory, State
from audit.models import Action, AuditLogEntry
from audit.retention import _audit_trigger_bypass
from audit.services import record
from comments import services as comment_services
from comments.models import AdvisoryComment


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    owner = make_user(email="owner@example.org")
    project = make_project("acme", team_members=[owner])
    advisory = Advisory.objects.create(project=project, summary="x", state=State.DRAFT)
    return {"owner": owner, "project": project, "advisory": advisory}


# ---------------------------------------------------------------------------
# Visibility policy
# ---------------------------------------------------------------------------


def test_tier_sets_are_disjoint_and_cover_no_excluded_actions():
    """Every timeline action belongs to exactly one tier; excluded actions belong to none."""
    a = tl.TIMELINE_ACTIONS_BY_TIER["viewer"]
    b = tl.TIMELINE_ACTIONS_BY_TIER["collaborator"] - a
    c = tl.TIMELINE_ACTIONS_BY_TIER["admin_owner"] - tl.TIMELINE_ACTIONS_BY_TIER["collaborator"]
    assert a.isdisjoint(b)
    assert (a | b).isdisjoint(c)
    assert tl.EXCLUDED_ACTIONS.isdisjoint(a | b | c)


def test_known_noisy_actions_are_excluded():
    """Sanity-check the events we explicitly do NOT want on the timeline."""
    must_exclude = {
        Action.ADVISORY_VIEWED,
        Action.COMMENT_CREATED,
        Action.COMMENT_EDITED,
        Action.COMMENT_REDACTED,
        Action.NOTIFICATION_PREFS_CHANGED,
        Action.PUBLICATION_OSV_GENERATED,
        Action.PUBLICATION_CSAF_GENERATED,
        Action.PUBLICATION_GIT_COMMIT,
        Action.GHSA_METADATA_FETCHED,
        Action.PMI_PROJECT_REPOS_SYNCED,
    }
    assert must_exclude.issubset(tl.EXCLUDED_ACTIONS)


@pytest.mark.django_db
def test_anonymous_user_has_no_visible_actions(setup):
    from django.contrib.auth.models import AnonymousUser

    assert tl.visible_actions(AnonymousUser(), setup["advisory"]) == frozenset()


@pytest.mark.django_db
def test_viewer_sees_only_tier_a(setup, make_user):
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    visible = tl.visible_actions(viewer, setup["advisory"])
    assert visible == tl.TIMELINE_ACTIONS_BY_TIER["viewer"]
    # Spot-check: tier B/C events are NOT visible.
    assert Action.ACCESS_GRANTED not in visible
    assert Action.PUBLICATION_EXPORT_FAILED not in visible
    assert Action.ADVISORY_TRIAGE_SUBMITTED not in visible


@pytest.mark.django_db
def test_collaborator_sees_tier_a_and_b(setup, make_user):
    collab = make_user(email="collab@example.org")
    grant_to_user(setup["advisory"], collab, AccessPermission.COLLABORATOR, by=setup["owner"])
    visible = tl.visible_actions(collab, setup["advisory"])
    assert Action.ADVISORY_PUBLISHED in visible
    assert Action.ACCESS_GRANTED in visible
    assert Action.PUBLICATION_EXPORT_FAILED in visible
    # Tier C still hidden.
    assert Action.ADVISORY_TRIAGE_SUBMITTED not in visible
    assert Action.ADVISORY_FLAGGED_FOR_ROUTING not in visible


@pytest.mark.django_db
def test_security_team_owner_sees_all_tiers(setup):
    visible = tl.visible_actions(setup["owner"], setup["advisory"])
    assert visible == tl.TIMELINE_ACTIONS_BY_TIER["admin_owner"]


@pytest.mark.django_db
def test_global_admin_sees_all_tiers_without_explicit_grant(setup, make_user, admin_group):
    admin = make_user(email="admin@example.org")
    admin.groups.add(admin_group)
    visible = tl.visible_actions(admin, setup["advisory"])
    assert visible == tl.TIMELINE_ACTIONS_BY_TIER["admin_owner"]


# ---------------------------------------------------------------------------
# Query filtering
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_events_for_advisory_excludes_actions_outside_visible_set(setup, make_user):
    viewer = make_user(email="v@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])

    # Tier A — should show
    record(action=Action.ADVISORY_CREATED, actor=setup["owner"], advisory=setup["advisory"])
    record(
        action=Action.ADVISORY_STATE_CHANGED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={"state": "draft"},
        new_value={"state": "published"},
    )
    # Tier B — should be hidden from viewer
    record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": viewer.pk, "permission": "viewer"},
    )
    record(action=Action.PUBLICATION_EXPORT_STARTED, advisory=setup["advisory"])
    # Tier C — should be hidden
    record(action=Action.ADVISORY_TRIAGE_SUBMITTED, advisory=setup["advisory"])
    # Excluded entirely — must never surface
    record(action=Action.ADVISORY_VIEWED, actor=viewer, advisory=setup["advisory"])
    record(
        action=Action.COMMENT_CREATED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        metadata={"length": 3},
    )

    events = list(tl.events_for_advisory(setup["advisory"], viewer=viewer))
    actions = [e.action for e in events]
    assert Action.ADVISORY_CREATED in actions
    assert Action.ADVISORY_STATE_CHANGED in actions
    assert Action.ACCESS_GRANTED not in actions
    assert Action.PUBLICATION_EXPORT_STARTED not in actions
    assert Action.ADVISORY_TRIAGE_SUBMITTED not in actions
    assert Action.ADVISORY_VIEWED not in actions
    assert Action.COMMENT_CREATED not in actions


@pytest.mark.django_db
def test_events_for_advisory_returns_chronological_order(setup):
    older = record(action=Action.ADVISORY_CREATED, actor=setup["owner"], advisory=setup["advisory"])
    newer = record(
        action=Action.ADVISORY_STATE_CHANGED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={"state": "draft"},
        new_value={"state": "published"},
    )
    # Force `older` to be older than `newer` regardless of creation order.
    _backdate_audit(older, newer.created_at - timedelta(minutes=5))
    events = list(tl.events_for_advisory(setup["advisory"], viewer=setup["owner"]))
    assert [e.pk for e in events] == [older.pk, newer.pk]


@pytest.mark.django_db
def test_events_for_advisory_returns_none_for_outsider(setup, make_user):
    outsider = make_user(email="out@example.org")
    record(action=Action.ADVISORY_CREATED, actor=setup["owner"], advisory=setup["advisory"])
    events = list(tl.events_for_advisory(setup["advisory"], viewer=outsider))
    assert events == []


# ---------------------------------------------------------------------------
# Summary formatters
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_summary_for_state_change(setup):
    e = record(
        action=Action.ADVISORY_STATE_CHANGED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={"state": "draft"},
        new_value={"state": "published"},
    )
    assert tl.summary_for(e) == "changed state from draft to published"


@pytest.mark.django_db
def test_summary_for_state_change_falls_back_for_review_status(setup):
    e = record(
        action=Action.ADVISORY_STATE_CHANGED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={"review_status": "approved"},
        new_value={"review_status": "none"},
    )
    assert "review status" in tl.summary_for(e)


@pytest.mark.django_db
def test_summary_for_access_granted_without_labels_falls_back(setup, make_user):
    user = make_user(email="x@example.org")
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": user.pk, "permission": "collaborator"},
    )
    # No principal_labels dict → generic phrasing.
    assert tl.summary_for(e) == "granted collaborator access to a user"


@pytest.mark.django_db
def test_summary_for_access_granted_uses_user_email(setup, make_user):
    user = make_user(email="bob@example.org")
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": user.pk, "permission": "viewer"},
    )
    labels = tl.resolve_principal_labels([e])
    assert tl.summary_for(e, labels) == "granted viewer access to bob@example.org"


@pytest.mark.django_db
def test_summary_for_access_granted_prefers_display_name(setup, make_user):
    user = make_user(email="bob@example.org")
    user.display_name = "Bob B"
    user.save(update_fields=["display_name"])
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": user.pk, "permission": "viewer"},
    )
    labels = tl.resolve_principal_labels([e])
    assert tl.summary_for(e, labels) == "granted viewer access to Bob B"


@pytest.mark.django_db
def test_summary_for_access_granted_uses_group_name(setup):
    from django.contrib.auth.models import Group

    group = Group.objects.create(name="auditors")
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={
            "principal_type": "group",
            "principal_id": group.pk,
            "permission": "collaborator",
        },
    )
    labels = tl.resolve_principal_labels([e])
    assert tl.summary_for(e, labels) == "granted collaborator access to auditors"


@pytest.mark.django_db
def test_summary_for_access_granted_falls_back_for_deleted_principal(setup):
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        # pk is a stable invalid PK — no user exists with this id.
        new_value={"principal_type": "user", "principal_id": 999_999, "permission": "viewer"},
    )
    labels = tl.resolve_principal_labels([e])
    assert tl.summary_for(e, labels) == "granted viewer access to a user"


@pytest.mark.django_db
def test_summary_for_access_granted_updated_metadata_uses_label(setup, make_user):
    user = make_user(email="bob@example.org")
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={"permission": "viewer"},
        new_value={
            "principal_type": "user",
            "principal_id": user.pk,
            "permission": "collaborator",
        },
        metadata={"updated": True},
    )
    labels = tl.resolve_principal_labels([e])
    assert tl.summary_for(e, labels) == "updated bob@example.org's access to collaborator"


@pytest.mark.django_db
def test_summary_for_access_revoked_uses_previous_value(setup, make_user):
    user = make_user(email="bob@example.org")
    e = record(
        action=Action.ACCESS_REVOKED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={
            "principal_type": "user",
            "principal_id": user.pk,
            "permission": "collaborator",
        },
    )
    labels = tl.resolve_principal_labels([e])
    assert tl.summary_for(e, labels) == "revoked collaborator access from bob@example.org"


@pytest.mark.django_db
def test_summary_chunks_for_access_granted_carries_live_user(setup, make_user):
    user = make_user(email="bob@example.org")
    user.display_name = "Bob B"
    user.save(update_fields=["display_name"])
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": user.pk, "permission": "viewer"},
    )
    principals = tl.resolve_principals([e])
    chunks = tl.summary_chunks_for(e, principals=principals)
    assert len(chunks) == 2
    assert chunks[0].text == "granted viewer access to "
    assert chunks[0].user is None and chunks[0].group is None
    assert chunks[1].text == "Bob B"
    assert chunks[1].user == user
    assert chunks[1].group is None
    # Joined chunks reproduce the plain-string summary verbatim.
    assert "".join(c.text for c in chunks) == tl.summary_for(
        e, principal_labels={k: v.label for k, v in principals.items()}
    )


@pytest.mark.django_db
def test_summary_chunks_for_access_granted_updated_has_three_chunks(setup, make_user):
    user = make_user(email="bob@example.org")
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={"permission": "viewer"},
        new_value={
            "principal_type": "user",
            "principal_id": user.pk,
            "permission": "collaborator",
        },
        metadata={"updated": True},
    )
    principals = tl.resolve_principals([e])
    chunks = tl.summary_chunks_for(e, principals=principals)
    assert [c.text for c in chunks] == ["updated ", "bob@example.org", "'s access to collaborator"]
    assert chunks[1].user == user


@pytest.mark.django_db
def test_summary_chunks_for_access_revoked_group_uses_group_chunk(setup):
    from django.contrib.auth.models import Group

    group = Group.objects.create(name="auditors")
    e = record(
        action=Action.ACCESS_REVOKED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={
            "principal_type": "group",
            "principal_id": group.pk,
            "permission": "collaborator",
        },
    )
    principals = tl.resolve_principals([e])
    chunks = tl.summary_chunks_for(e, principals=principals)
    assert [c.text for c in chunks] == ["revoked collaborator access from ", "auditors"]
    assert chunks[1].user is None
    assert chunks[1].group == group


@pytest.mark.django_db
def test_summary_chunks_for_deleted_principal_is_plain_text(setup):
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": 999_999, "permission": "viewer"},
    )
    principals = tl.resolve_principals([e])  # principal missing → empty dict
    chunks = tl.summary_chunks_for(e, principals=principals)
    # The principal portion degrades to a plain-text chunk; no chip rendered.
    assert chunks[-1].text == "a user"
    assert chunks[-1].user is None and chunks[-1].group is None


@pytest.mark.django_db
def test_summary_chunks_for_non_access_action_is_one_text_chunk(setup):
    e = record(action=Action.ADVISORY_PUBLISHED, actor=setup["owner"], advisory=setup["advisory"])
    chunks = tl.summary_chunks_for(e)
    assert len(chunks) == 1
    assert chunks[0].text == "published this advisory"
    assert chunks[0].user is None and chunks[0].group is None


@pytest.mark.django_db
def test_coalesced_chunks_interleaves_principal_chunks(setup, make_user):
    from django.contrib.auth.models import Group

    a = make_user(email="alice@example.org")
    a.display_name = "Alice"
    a.save(update_fields=["display_name"])
    b = make_user(email="bob@example.org")
    grp = Group.objects.create(name="auditors")
    events = [
        record(
            action=Action.ACCESS_GRANTED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={"principal_type": "user", "principal_id": a.pk, "permission": "viewer"},
        ),
        record(
            action=Action.ACCESS_GRANTED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={"principal_type": "user", "principal_id": b.pk, "permission": "viewer"},
        ),
        record(
            action=Action.ACCESS_GRANTED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={"principal_type": "group", "principal_id": grp.pk, "permission": "viewer"},
        ),
    ]
    principals = tl.resolve_principals(events)
    chunks = tl.coalesced_chunks(events, principals)
    # Prose reads "granted viewer access to Alice, bob@example.org, and auditors".
    joined = "".join(c.text for c in chunks)
    assert joined == "granted viewer access to Alice, bob@example.org, and auditors"
    # The two user chunks carry their live User; the group chunk carries the Group.
    chip_users = [c.user for c in chunks if c.user is not None]
    chip_groups = [c.group for c in chunks if c.group is not None]
    assert set(chip_users) == {a, b}
    assert chip_groups == [grp]


@pytest.mark.django_db
def test_coalesced_chunks_truncates_past_limit(setup, make_user):
    users = [make_user(email=f"u{i}@example.org") for i in range(5)]
    events = [
        record(
            action=Action.ACCESS_GRANTED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={"principal_type": "user", "principal_id": u.pk, "permission": "viewer"},
        )
        for u in users
    ]
    principals = tl.resolve_principals(events)
    chunks = tl.coalesced_chunks(events, principals)
    joined = "".join(c.text for c in chunks)
    # Only the first 3 names appear; remaining 2 are summed.
    assert joined.startswith(
        "granted viewer access to u0@example.org, u1@example.org, u2@example.org, and 2 more"
    )
    # And only those first three chunks carry live User references.
    chip_users = [c.user for c in chunks if c.user is not None]
    assert set(chip_users) == {users[0], users[1], users[2]}


@pytest.mark.django_db
def test_resolve_principals_returns_live_objects_with_groups_prefetched(setup, make_user):
    from django.contrib.auth.models import Group
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    u = make_user(email="bob@example.org")
    grp = Group.objects.create(name="auditors")
    u.groups.add(grp)
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": u.pk, "permission": "viewer"},
    )
    principals = tl.resolve_principals([e])
    p = principals[("user", u.pk)]
    assert p.user == u
    assert p.label == "bob@example.org"
    # The User's groups M2M should be prefetched: iterating .all() must not
    # trigger an additional query.
    with CaptureQueriesContext(connection) as ctx:
        names = [g.name for g in p.user.groups.all()]
    assert names == ["auditors"]
    assert len(ctx.captured_queries) == 0


@pytest.mark.django_db
def test_timeline_event_renders_chunks_with_chip_inside_summary(client, setup, make_user):
    """End-to-end smoke: render _event.html and confirm the principal of an
    ACCESS_GRANTED row appears as a user-chip *inside* the summary span."""
    from django.template.loader import render_to_string

    bob = make_user(email="bob@example.org")
    bob.display_name = "Bob B"
    bob.save(update_fields=["display_name"])
    e = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": bob.pk, "permission": "viewer"},
    )
    principals = tl.resolve_principals([e])
    event = tl.TimelineEvent.from_entry(e, principals=principals)
    # Render as an owner would see it (viewer_can_see_emails) so the chip reveals
    # its full form; a non-owner gets the same chip rendered plain (tested in
    # test_user_display.py).
    html = render_to_string(
        "comments/_event.html",
        {"event": event, "advisory": setup["advisory"], "viewer_can_see_emails": True},
    )
    # The summary span exists.
    assert 'class="timeline-event__summary"' in html
    # And a user-chip is rendered *inside* it (not just on the actor).
    summary_open = html.find('class="timeline-event__summary"')
    summary_close = html.find("</span>", summary_open)
    assert summary_open < summary_close
    assert 'class="user-chip"' in html[summary_open:summary_close]
    assert "Bob B" in html[summary_open:summary_close]


@pytest.mark.django_db
def test_invitation_prose_email_masked_for_non_owner(setup):
    """An invitation event has no user principal to chip-mask, so its target
    email lives in plain prose; non-owners must see it masked (INV-PRIVACY-4)."""
    e = record(
        action=Action.INVITATION_CREATED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"email": "newuser@example.org", "permission": "viewer"},
    )
    owner_text = " ".join(
        c.text for c in tl.TimelineEvent.from_entry(e, show_emails=True).summary_chunks
    )
    assert "newuser@example.org" in owner_text

    masked_text = " ".join(
        c.text for c in tl.TimelineEvent.from_entry(e, show_emails=False).summary_chunks
    )
    assert "newuser@example.org" not in masked_text
    assert "n•••@example.org" in masked_text


@pytest.mark.django_db
def test_advisory_timeline_masks_invitation_email_for_collaborator(setup, make_user):
    """End-to-end: a collaborator sees invitation events (tier B) but never the
    invited email; the owner still does."""
    collaborator = make_user(email="collab@example.org")
    grant_to_user(setup["advisory"], collaborator, AccessPermission.COLLABORATOR, by=setup["owner"])
    record(
        action=Action.INVITATION_CREATED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"email": "secret-invitee@example.org", "permission": "viewer"},
    )

    def _invitation_text(viewer):
        items = comment_services.advisory_timeline(setup["advisory"], viewer=viewer)
        inv = [
            it["obj"]
            for it in items
            if it["kind"] == "event" and it["obj"].action == Action.INVITATION_CREATED
        ]
        assert inv, "collaborator should see the invitation event (tier B)"
        return " ".join(c.text for c in inv[0].summary_chunks)

    collab_text = _invitation_text(collaborator)
    assert "secret-invitee@example.org" not in collab_text
    assert "s•••@example.org" in collab_text

    assert "secret-invitee@example.org" in _invitation_text(setup["owner"])


@pytest.mark.django_db
def test_summary_for_invitation_created_uses_email_from_payload(setup):
    e = record(
        action=Action.INVITATION_CREATED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"email": "newuser@example.org", "permission": "viewer"},
    )
    # Invitations don't need the labels dict — email is in the payload.
    assert tl.summary_for(e) == "invited newuser@example.org with viewer access"


@pytest.mark.django_db
def test_summary_for_invitation_created_updated_uses_email(setup):
    e = record(
        action=Action.INVITATION_CREATED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={"permission": "viewer"},
        new_value={"email": "newuser@example.org", "permission": "collaborator"},
        metadata={"updated": True},
    )
    assert (
        tl.summary_for(e)
        == "updated the pending invitation for newuser@example.org to collaborator"
    )


@pytest.mark.django_db
def test_summary_for_invitation_revoked_uses_previous_value_email(setup):
    e = record(
        action=Action.INVITATION_REVOKED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={"email": "gone@example.org", "permission": "viewer"},
    )
    assert tl.summary_for(e) == "revoked the pending invitation for gone@example.org"


@pytest.mark.django_db
def test_resolve_principal_labels_batches_queries(setup, make_user, django_assert_num_queries):
    """One query per principal kind regardless of how many access events exist."""
    from django.contrib.auth.models import Group

    u1 = make_user(email="u1@example.org")
    u2 = make_user(email="u2@example.org")
    g1 = Group.objects.create(name="g1")
    g2 = Group.objects.create(name="g2")

    events = [
        record(
            action=Action.ACCESS_GRANTED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={"principal_type": "user", "principal_id": u1.pk, "permission": "viewer"},
        ),
        record(
            action=Action.ACCESS_GRANTED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={"principal_type": "user", "principal_id": u2.pk, "permission": "viewer"},
        ),
        record(
            action=Action.ACCESS_GRANTED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={
                "principal_type": "group",
                "principal_id": g1.pk,
                "permission": "viewer",
            },
        ),
        record(
            action=Action.ACCESS_REVOKED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            previous_value={
                "principal_type": "group",
                "principal_id": g2.pk,
                "permission": "viewer",
            },
        ),
    ]

    with django_assert_num_queries(2):
        labels = tl.resolve_principal_labels(events)

    assert labels[("user", u1.pk)] == "u1@example.org"
    assert labels[("user", u2.pk)] == "u2@example.org"
    assert labels[("group", g1.pk)] == "g1"
    assert labels[("group", g2.pk)] == "g2"


@pytest.mark.django_db
def test_summary_for_dismissed_includes_reason(setup):
    e = record(
        action=Action.ADVISORY_DISMISSED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        metadata={"reason": "duplicate"},
    )
    assert tl.summary_for(e) == "dismissed this advisory: duplicate"


@pytest.mark.django_db
def test_summary_for_unknown_action_falls_back_to_action_name(setup):
    e = record(
        action=Action.PUBLICATION_GIT_PUSH,
        advisory=setup["advisory"],
        new_value={"commit_sha": "abc"},
    )
    # PUBLICATION_GIT_PUSH has a formatter, so this returns the verb.
    assert tl.summary_for(e) == "pushed advisory artifacts to the publication repo"


@pytest.mark.django_db
def test_timeline_event_actor_label_falls_back_to_system_for_null_actor(setup):
    e = record(action=Action.PUBLICATION_GIT_PUSH, advisory=setup["advisory"])
    wrapped = tl.TimelineEvent.from_entry(e)
    assert wrapped.actor_label == "system"


@pytest.mark.django_db
def test_timeline_event_prefers_display_name(setup):
    setup["owner"].display_name = "Alice Owner"
    setup["owner"].save(update_fields=["display_name"])
    e = record(action=Action.ADVISORY_PUBLISHED, actor=setup["owner"], advisory=setup["advisory"])
    wrapped = tl.TimelineEvent.from_entry(e)
    assert wrapped.actor_label == "Alice Owner"


@pytest.mark.django_db
def test_timeline_event_exposes_actor_user(setup):
    """The wrapped event carries the live User so templates can render a
    chip with email + groups on hover (not just the plain label)."""
    e = record(action=Action.ADVISORY_PUBLISHED, actor=setup["owner"], advisory=setup["advisory"])
    wrapped = tl.TimelineEvent.from_entry(e)
    assert wrapped.actor == setup["owner"]


@pytest.mark.django_db
def test_timeline_event_actor_is_none_for_system_action(setup):
    e = record(action=Action.PUBLICATION_GIT_PUSH, advisory=setup["advisory"])
    wrapped = tl.TimelineEvent.from_entry(e)
    assert wrapped.actor is None
    assert wrapped.actor_label == "system"


# ---------------------------------------------------------------------------
# Merge with comments
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_advisory_timeline_interleaves_comments_and_events(setup):
    advisory = setup["advisory"]
    owner = setup["owner"]
    t0 = timezone.now()

    e1 = record(action=Action.ADVISORY_CREATED, actor=owner, advisory=advisory)
    c1 = comment_services.add_comment(advisory, author=owner, body="first comment")
    e2 = record(
        action=Action.ADVISORY_STATE_CHANGED,
        actor=owner,
        advisory=advisory,
        previous_value={"state": "draft"},
        new_value={"state": "published"},
    )
    c2 = comment_services.add_comment(advisory, author=owner, body="second comment")

    # Backdate to enforce a deterministic ordering: e1 < c1 < e2 < c2.
    _backdate_audit(e1, t0 + timedelta(seconds=1))
    _backdate_comment(c1, t0 + timedelta(seconds=2))
    _backdate_audit(e2, t0 + timedelta(seconds=3))
    _backdate_comment(c2, t0 + timedelta(seconds=4))

    items = comment_services.advisory_timeline(advisory, viewer=owner)
    kinds = [i["kind"] for i in items]
    assert kinds == ["event", "comment", "event", "comment"]
    # Comment objects in the result are full AdvisoryComment instances.
    assert items[1]["obj"].body == "first comment"
    # Event objects are wrapped TimelineEvent dataclasses.
    assert items[0]["obj"].action == Action.ADVISORY_CREATED


@pytest.mark.django_db
def test_advisory_timeline_breaks_ties_with_comment_first(setup):
    """At identical timestamps a comment renders before an event."""
    advisory = setup["advisory"]
    owner = setup["owner"]
    same = timezone.now()
    c = comment_services.add_comment(advisory, author=owner, body="hi")
    e = record(action=Action.ADVISORY_CREATED, actor=owner, advisory=advisory)
    _backdate_comment(c, same)
    _backdate_audit(e, same)

    items = comment_services.advisory_timeline(advisory, viewer=owner)
    assert [i["kind"] for i in items] == ["comment", "event"]


@pytest.mark.django_db
def test_advisory_timeline_preserves_internal_comment_filter(setup, make_user):
    """Viewers continue to be blocked from seeing internal comments via the timeline."""
    advisory = setup["advisory"]
    viewer = make_user(email="v2@example.org")
    grant_to_user(advisory, viewer, AccessPermission.VIEWER, by=setup["owner"])

    comment_services.add_comment(advisory, author=setup["owner"], body="public")
    comment_services.add_comment(advisory, author=setup["owner"], body="secret", internal=True)

    items = comment_services.advisory_timeline(advisory, viewer=viewer)
    bodies = [i["obj"].body for i in items if i["kind"] == "comment"]
    assert bodies == ["public"]


@pytest.mark.django_db
def test_advisory_timeline_does_not_duplicate_comments_as_events(setup):
    """``comment.created`` audit rows must not produce a second event row."""
    advisory = setup["advisory"]
    owner = setup["owner"]
    comment_services.add_comment(advisory, author=owner, body="hello")
    items = comment_services.advisory_timeline(advisory, viewer=owner)
    assert len([i for i in items if i["kind"] == "comment"]) == 1
    assert all(i["kind"] != "event" or i["obj"].action != Action.COMMENT_CREATED for i in items)


# ---------------------------------------------------------------------------
# HTMX view
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_timeline_view_renders_for_authorized_user(client, setup):
    client.force_login(setup["owner"])
    record(action=Action.ADVISORY_PUBLISHED, actor=setup["owner"], advisory=setup["advisory"])
    response = client.get(reverse("comments:timeline", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 200
    assert b"published this advisory" in response.content


@pytest.mark.django_db
def test_timeline_view_filters_by_role(client, setup, make_user):
    viewer = make_user(email="vw@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": viewer.pk, "permission": "viewer"},
    )

    client.force_login(viewer)
    response = client.get(reverse("comments:timeline", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 200
    # Tier-B action hidden from viewer.
    assert b"granted" not in response.content


@pytest.mark.django_db
def test_timeline_view_rejects_outsider(client, setup, make_user):
    outsider = make_user(email="zz@example.org")
    client.force_login(outsider)
    response = client.get(reverse("comments:timeline", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Coalescing
# ---------------------------------------------------------------------------


def _backdate_audit(entry, when):
    # The append-only Postgres trigger forbids UPDATE on audit_auditlogentry;
    # lower session_replication_role for this one backdating write. Same
    # escape hatch production code uses (audit.retention).
    with _audit_trigger_bypass():
        AuditLogEntry.objects.filter(pk=entry.pk).update(created_at=when)


def _backdate_comment(comment, when):
    with _audit_trigger_bypass():
        AdvisoryComment.objects.filter(pk=comment.pk).update(created_at=when)


def _emit_edited(advisory, *, actor, version, at):
    e = record(
        action=Action.ADVISORY_EDITED,
        actor=actor,
        advisory=advisory,
        new_value={"version": version, "state": "draft"},
    )
    _backdate_audit(e, at)
    return e


@pytest.mark.django_db
def test_advisory_edited_coalesces_into_version_range(setup):
    t0 = timezone.now()
    for offset, v in enumerate((2, 3, 4), start=1):
        _emit_edited(
            setup["advisory"], actor=setup["owner"], version=v, at=t0 + timedelta(minutes=offset)
        )
    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    assert len(events) == 1
    assert events[0]["obj"].summary == "edited the advisory (versions 2–4)"
    assert events[0]["ts"] == t0 + timedelta(minutes=3)


@pytest.mark.django_db
def test_coalesce_breaks_on_interleaved_comment(setup):
    t0 = timezone.now()
    _emit_edited(setup["advisory"], actor=setup["owner"], version=2, at=t0 + timedelta(minutes=1))
    c = comment_services.add_comment(setup["advisory"], author=setup["owner"], body="halt")
    _backdate_comment(c, t0 + timedelta(minutes=2))
    _emit_edited(setup["advisory"], actor=setup["owner"], version=3, at=t0 + timedelta(minutes=3))

    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    # Comment broke the run — two separate edit rows.
    assert len(events) == 2
    assert events[0]["obj"].summary == "edited the advisory (version 2)"
    assert events[1]["obj"].summary == "edited the advisory (version 3)"


@pytest.mark.django_db
def test_coalesce_breaks_on_different_actor(setup, make_user):
    bob = make_user(email="bob@example.org")
    setup["project"].security_team.user_set.add(bob)
    t0 = timezone.now()
    _emit_edited(setup["advisory"], actor=setup["owner"], version=2, at=t0 + timedelta(minutes=1))
    _emit_edited(setup["advisory"], actor=bob, version=3, at=t0 + timedelta(minutes=2))

    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    assert len(events) == 2


@pytest.mark.django_db
def test_coalesce_breaks_on_different_action(setup):
    t0 = timezone.now()
    _emit_edited(setup["advisory"], actor=setup["owner"], version=2, at=t0 + timedelta(minutes=1))
    state_change = record(
        action=Action.ADVISORY_STATE_CHANGED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        previous_value={"state": "draft"},
        new_value={"state": "draft"},
    )
    _backdate_audit(state_change, t0 + timedelta(minutes=2))
    _emit_edited(setup["advisory"], actor=setup["owner"], version=3, at=t0 + timedelta(minutes=3))

    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    # state_change splits the two edits.
    assert len(events) == 3


@pytest.mark.django_db
def test_advisory_edited_breaks_run_on_version_gap(setup):
    t0 = timezone.now()
    for offset, v in enumerate((2, 3, 5, 6), start=1):
        _emit_edited(
            setup["advisory"], actor=setup["owner"], version=v, at=t0 + timedelta(minutes=offset)
        )
    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    assert [e["obj"].summary for e in events] == [
        "edited the advisory (versions 2–3)",
        "edited the advisory (versions 5–6)",
    ]


@pytest.mark.django_db
def test_coalesce_access_grants_with_same_permission_and_type(setup, make_user):
    t0 = timezone.now()
    targets = [make_user(email=f"u{i}@example.org") for i in range(3)]
    for offset, u in enumerate(targets, start=1):
        e = record(
            action=Action.ACCESS_GRANTED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={
                "principal_type": "user",
                "principal_id": u.pk,
                "permission": "viewer",
            },
        )
        _backdate_audit(e, t0 + timedelta(minutes=offset))
    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    assert len(events) == 1
    summary = events[0]["obj"].summary
    assert summary.startswith("granted viewer access to ")
    for u in targets:
        assert u.email in summary


@pytest.mark.django_db
def test_coalesce_access_grants_truncates_after_three_targets(setup, make_user):
    t0 = timezone.now()
    targets = [make_user(email=f"u{i}@example.org") for i in range(5)]
    for offset, u in enumerate(targets, start=1):
        e = record(
            action=Action.ACCESS_GRANTED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={
                "principal_type": "user",
                "principal_id": u.pk,
                "permission": "viewer",
            },
        )
        _backdate_audit(e, t0 + timedelta(minutes=offset))
    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    assert len(events) == 1
    summary = events[0]["obj"].summary
    assert "and 2 more" in summary
    # The first three should be listed; the last two should NOT be.
    for u in targets[:3]:
        assert u.email in summary
    for u in targets[3:]:
        assert u.email not in summary


@pytest.mark.django_db
def test_coalesce_access_grants_breaks_on_different_permission(setup, make_user):
    t0 = timezone.now()
    u1 = make_user(email="u1@example.org")
    u2 = make_user(email="u2@example.org")
    e1 = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": u1.pk, "permission": "viewer"},
    )
    e2 = record(
        action=Action.ACCESS_GRANTED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"principal_type": "user", "principal_id": u2.pk, "permission": "collaborator"},
    )
    _backdate_audit(e1, t0 + timedelta(minutes=1))
    _backdate_audit(e2, t0 + timedelta(minutes=2))
    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    assert len(events) == 2


@pytest.mark.django_db
def test_coalesce_invitation_created_with_email_payload(setup):
    t0 = timezone.now()
    emails = ["a@example.org", "b@example.org", "c@example.org"]
    for offset, email in enumerate(emails, start=1):
        e = record(
            action=Action.INVITATION_CREATED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={"email": email, "permission": "viewer"},
        )
        _backdate_audit(e, t0 + timedelta(minutes=offset))
    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    assert len(events) == 1
    summary = events[0]["obj"].summary
    for email in emails:
        assert email in summary
    assert "viewer" in summary


@pytest.mark.django_db
def test_coalesce_publication_export_failed_counts(setup):
    t0 = timezone.now()
    for offset in range(1, 4):
        e = record(
            action=Action.PUBLICATION_EXPORT_FAILED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            metadata={"error": "boom"},
        )
        _backdate_audit(e, t0 + timedelta(minutes=offset))
    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    assert len(events) == 1
    assert events[0]["obj"].summary == "publication export failed 3 times"


@pytest.mark.django_db
def test_non_coalescable_actions_render_one_row_each(setup):
    """Regression guard: state changes must not silently start coalescing."""
    t0 = timezone.now()
    for offset, (prev, new) in enumerate(
        (("triage", "draft"), ("draft", "published"), ("published", "dismissed")), start=1
    ):
        e = record(
            action=Action.ADVISORY_STATE_CHANGED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            previous_value={"state": prev},
            new_value={"state": new},
        )
        _backdate_audit(e, t0 + timedelta(minutes=offset))
    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    assert len(events) == 3


# ---------------------------------------------------------------------------
# Changed-field rendering on advisory.edited
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_advisory_edited_single_field_change_renders_field_label(setup):
    e = record(
        action=Action.ADVISORY_EDITED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"version": 2},
        metadata={"changed_fields": ["cwe_ids"]},
    )
    assert tl.summary_for(e) == "edited the advisory's CWE list (version 2)"


@pytest.mark.django_db
def test_advisory_edited_multiple_field_changes_use_english_list(setup):
    e = record(
        action=Action.ADVISORY_EDITED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"version": 3},
        metadata={"changed_fields": ["summary", "cwe_ids", "severity"]},
    )
    # English-list join: ", and " before the last item.
    assert tl.summary_for(e) == "edited the advisory's summary, CWE list, and severity (version 3)"


@pytest.mark.django_db
def test_advisory_edited_two_fields_use_simple_and(setup):
    e = record(
        action=Action.ADVISORY_EDITED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"version": 4},
        metadata={"changed_fields": ["details", "affected"]},
    )
    assert (
        tl.summary_for(e) == "edited the advisory's description and affected packages (version 4)"
    )


@pytest.mark.django_db
def test_advisory_edited_unknown_field_falls_back_to_raw_key(setup):
    """Future payload keys without a label entry must degrade, not crash."""
    e = record(
        action=Action.ADVISORY_EDITED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"version": 5},
        metadata={"changed_fields": ["new_unmapped_field"]},
    )
    assert tl.summary_for(e) == "edited the advisory's new_unmapped_field (version 5)"


@pytest.mark.django_db
def test_advisory_edited_empty_changed_fields_falls_back(setup):
    """Missing or empty changed_fields keeps the legacy summary."""
    e = record(
        action=Action.ADVISORY_EDITED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"version": 6},
        metadata={"changed_fields": []},
    )
    assert tl.summary_for(e) == "edited the advisory (version 6)"


@pytest.mark.django_db
def test_advisory_edited_missing_metadata_falls_back(setup):
    e = record(
        action=Action.ADVISORY_EDITED,
        actor=setup["owner"],
        advisory=setup["advisory"],
        new_value={"version": 7},
    )
    assert tl.summary_for(e) == "edited the advisory (version 7)"


@pytest.mark.django_db
def test_coalesce_advisory_edited_unions_changed_fields(setup):
    """Coalesced run unions changed_fields, preserves first-seen order, dedupes."""
    t0 = timezone.now()
    field_sets = [
        ["summary"],
        ["cwe_ids", "severity"],
        ["summary"],  # duplicate — should not appear twice
    ]
    for offset, (v, fields) in enumerate(zip((2, 3, 4), field_sets, strict=True), start=1):
        e = record(
            action=Action.ADVISORY_EDITED,
            actor=setup["owner"],
            advisory=setup["advisory"],
            new_value={"version": v},
            metadata={"changed_fields": fields},
        )
        _backdate_audit(e, t0 + timedelta(minutes=offset))
    items = comment_services.advisory_timeline(setup["advisory"], viewer=setup["owner"])
    events = [i for i in items if i["kind"] == "event"]
    assert len(events) == 1
    assert (
        events[0]["obj"].summary
        == "edited the advisory's summary, CWE list, and severity (versions 2–4)"
    )


# ---------------------------------------------------------------------------
# changed_payload_fields helper
# ---------------------------------------------------------------------------


def test_changed_payload_fields_returns_empty_when_no_prior_payload():
    from advisories.services import changed_payload_fields

    assert changed_payload_fields(None, {"summary": "x"}) == []
    assert changed_payload_fields({}, {"summary": "x"}) == []


def test_changed_payload_fields_returns_diff_keys_sorted():
    from advisories.services import changed_payload_fields

    old = {"summary": "old", "details": "same", "cwe_ids": ["CWE-79"]}
    new = {"summary": "new", "details": "same", "cwe_ids": ["CWE-89", "CWE-90"]}
    assert changed_payload_fields(old, new) == ["cwe_ids", "summary"]


def test_changed_payload_fields_handles_identical_payloads():
    from advisories.services import changed_payload_fields

    payload = {"summary": "x", "cwe_ids": ["CWE-79"]}
    assert changed_payload_fields(payload, payload) == []
    assert changed_payload_fields(dict(payload), dict(payload)) == []
