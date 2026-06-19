"""Modal action notes surface in the Activity pane as author-attributed comments.

Covers the reusable ``comments.services.record_action_note`` helper (blank /
no-author no-ops, the ``is_internal`` flag, the comment-lock/​rank bypass) and
the per-action wiring across ``advisories.services`` and ``workflows.services``,
asserting each note lands as a comment with the documented public/internal
visibility (requirements.md §AdvisoryComment).
"""

from __future__ import annotations

import pytest

from access.models import Permission as AccessPermission
from access.services import grant_to_user
from advisories import services
from advisories import timeline as tl
from advisories.models import Advisory, State
from audit.models import Action
from comments.models import AdvisoryComment
from comments.services import comments_for_advisory, record_action_note
from workflows import services as wf
from workflows.models import CveRequestStatus


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    owner = make_user(email="owner@example.org")
    project = make_project("acme", team_members=[owner])
    advisory = Advisory.objects.create(
        project=project, summary="x", state=State.DRAFT, created_by=owner
    )
    return {"admin": admin, "owner": owner, "project": project, "advisory": advisory}


def _comments(advisory):
    return AdvisoryComment.objects.filter(advisory=advisory).order_by("created_at")


def _timeline_actions(advisory, viewer):
    return [e.action for e in tl.events_for_advisory(advisory, viewer=viewer)]


# ---------------------------------------------------------------------------
# record_action_note helper
# ---------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("body", ["", "   ", "\n\t "])
def test_record_action_note_blank_body_creates_no_comment(setup, body):
    assert record_action_note(setup["advisory"], author=setup["owner"], body=body) is None
    assert not _comments(setup["advisory"]).exists()


@pytest.mark.django_db
def test_record_action_note_none_author_creates_no_comment(setup):
    # System-policy actions (GHSA auto-dismiss/withdraw) have no human author.
    assert record_action_note(setup["advisory"], author=None, body="reason") is None
    assert not _comments(setup["advisory"]).exists()


@pytest.mark.django_db
def test_record_action_note_strips_and_sets_internal_flag(setup):
    pub = record_action_note(
        setup["advisory"], author=setup["owner"], body="  hi  ", internal=False
    )
    intern = record_action_note(
        setup["advisory"], author=setup["owner"], body="hush", internal=True
    )
    assert pub.body == "hi"
    assert pub.is_internal is False
    assert intern.is_internal is True
    assert intern.author == setup["owner"]


@pytest.mark.django_db
def test_record_action_note_bypasses_comment_lock_and_rank(setup, make_user):
    # A viewer normally can't comment at all once comments are locked, and can
    # never post an internal comment — but a system action note must still land.
    viewer = make_user(email="v@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"])
    setup["advisory"].refresh_from_db()

    comment = record_action_note(
        setup["advisory"], author=viewer, body="system note", internal=True
    )
    assert comment is not None
    assert comment.is_internal is True


# ---------------------------------------------------------------------------
# advisories.services wiring — public notes
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_dismiss_triage_posts_public_comment(setup):
    adv = Advisory.objects.create(
        project=setup["project"], summary="t", state=State.TRIAGE, created_by=setup["owner"]
    )
    services.dismiss_triage(adv, by=setup["owner"], reason="spam report")
    comment = _comments(adv).get()
    assert comment.is_internal is False
    assert comment.author == setup["owner"]
    assert comment.body == "spam report"


@pytest.mark.django_db
def test_dismiss_advisory_posts_public_comment(setup):
    services.dismiss_advisory(setup["advisory"], by=setup["owner"], reason="false positive")
    comment = _comments(setup["advisory"]).get()
    assert comment.is_internal is False
    assert comment.body == "false positive"


@pytest.mark.django_db
def test_lock_comments_with_reason_posts_public_comment(setup):
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"], reason="cool down")
    comment = _comments(setup["advisory"]).get()
    assert comment.is_internal is False
    assert comment.body == "cool down"


@pytest.mark.django_db
def test_lock_comments_without_reason_posts_no_comment(setup):
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"])
    assert not _comments(setup["advisory"]).exists()


# ---------------------------------------------------------------------------
# advisories.services wiring — internal notes
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_flag_for_admin_routing_posts_internal_comment(setup):
    adv = Advisory.objects.create(
        project=setup["project"], summary="t", state=State.TRIAGE, created_by=setup["owner"]
    )
    services.flag_for_admin_routing(adv, by=setup["owner"], note="belongs to another team")
    comment = _comments(adv).get()
    assert comment.is_internal is True
    assert comment.body == "belongs to another team"


@pytest.mark.django_db
def test_clear_routing_flag_with_note_posts_internal_comment(setup):
    adv = Advisory.objects.create(
        project=setup["project"], summary="t", state=State.TRIAGE, created_by=setup["owner"]
    )
    services.flag_for_admin_routing(adv, by=setup["owner"], note="flag note")
    services.clear_admin_routing_flag(adv, by=setup["owner"], note="resolved, ours after all")
    bodies = [c.body for c in _comments(adv)]
    assert bodies == ["flag note", "resolved, ours after all"]
    assert all(c.is_internal for c in _comments(adv))


@pytest.mark.django_db
def test_clear_routing_flag_blank_note_posts_no_comment(setup):
    adv = Advisory.objects.create(
        project=setup["project"], summary="t", state=State.TRIAGE, created_by=setup["owner"]
    )
    services.flag_for_admin_routing(adv, by=setup["owner"], note="flag note")
    services.clear_admin_routing_flag(adv, by=setup["owner"])
    # Only the flag note comment — the blank clear note adds nothing.
    assert [c.body for c in _comments(adv)] == ["flag note"]


@pytest.mark.django_db
def test_request_reassignment_posts_internal_comment(setup):
    services.request_admin_reassignment(setup["advisory"], by=setup["owner"], note="wrong project")
    comment = _comments(setup["advisory"]).get()
    assert comment.is_internal is True
    assert comment.body == "wrong project"


@pytest.mark.django_db
def test_withdraw_reassignment_blank_note_posts_no_comment(setup):
    services.request_admin_reassignment(setup["advisory"], by=setup["owner"], note="wrong project")
    services.withdraw_admin_reassignment(setup["advisory"], by=setup["owner"])
    assert [c.body for c in _comments(setup["advisory"])] == ["wrong project"]


@pytest.mark.django_db
def test_request_withdrawal_posts_internal_comment(make_user, make_project):
    project = make_project("beta")  # non-mature → owner must request, not withdraw
    owner = make_user(email="o2@example.org", groups=[f"{project.slug}-security"])
    adv = Advisory.objects.create(project=project, summary="x", state=State.PUBLISHED)
    services.request_withdrawal(adv, by=owner, note="superseded by a fix")
    comment = _comments(adv).get()
    assert comment.is_internal is True
    assert comment.body == "superseded by a fix"


@pytest.mark.django_db
def test_cancel_withdrawal_blank_note_posts_no_comment(make_user, make_project):
    project = make_project("beta")
    owner = make_user(email="o3@example.org", groups=[f"{project.slug}-security"])
    adv = Advisory.objects.create(project=project, summary="x", state=State.PUBLISHED)
    services.request_withdrawal(adv, by=owner, note="please withdraw")
    services.cancel_withdrawal_request(adv, by=owner)
    assert [c.body for c in _comments(adv)] == ["please withdraw"]


# ---------------------------------------------------------------------------
# workflows.services wiring
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_review_approve_with_notes_posts_public_comment(setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["owner"])
    wf.approve_review(task, by=setup["admin"], notes="LGTM, ship it")
    comment = _comments(setup["advisory"]).get()
    assert comment.is_internal is False
    assert comment.author == setup["admin"]
    assert comment.body == "LGTM, ship it"


@pytest.mark.django_db
def test_review_approve_without_notes_posts_no_comment(setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["owner"])
    wf.approve_review(task, by=setup["admin"])
    assert not _comments(setup["advisory"]).exists()


@pytest.mark.django_db
def test_review_request_changes_with_notes_posts_public_comment(setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["owner"])
    wf.request_changes(task, by=setup["admin"], notes="add affected versions")
    comment = _comments(setup["advisory"]).get()
    assert comment.is_internal is False
    assert comment.body == "add affected versions"


@pytest.mark.django_db
def test_revoke_approval_with_reason_posts_internal_comment(setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["owner"])
    wf.approve_review(task, by=setup["admin"])
    wf.revoke_approval(setup["advisory"], by=setup["admin"], reason="needs another look")
    comment = _comments(setup["advisory"]).get()
    assert comment.is_internal is True
    assert comment.body == "needs another look"


@pytest.mark.django_db
def test_revoke_approval_without_reason_posts_no_comment(setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["owner"])
    wf.approve_review(task, by=setup["admin"])
    wf.revoke_approval(setup["advisory"], by=setup["admin"])
    assert not _comments(setup["advisory"]).exists()


@pytest.mark.django_db
def test_unassign_cve_posts_internal_comment(setup):
    task = wf.request_cve(setup["advisory"], by=setup["owner"])
    wf.transition_cve_request(
        task, by=setup["admin"], new_status=CveRequestStatus.RESERVED, cve_id="CVE-2026-9999"
    )
    wf.unassign_cve(setup["advisory"], by=setup["admin"], reason="reserved on wrong advisory")
    comment = _comments(setup["advisory"]).get()
    assert comment.is_internal is True
    assert comment.body == "reserved on wrong advisory"


# ---------------------------------------------------------------------------
# Visibility
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_viewer_sees_public_action_note_but_not_internal(setup, make_user):
    viewer = make_user(email="reader@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    # One public note (review feedback) and one internal note (revoke reason).
    task = wf.submit_for_review(setup["advisory"], by=setup["owner"])
    wf.request_changes(task, by=setup["admin"], notes="public feedback")
    services.request_admin_reassignment(setup["advisory"], by=setup["owner"], note="internal note")

    visible = {c.body for c in comments_for_advisory(setup["advisory"], viewer=viewer)}
    assert "public feedback" in visible
    assert "internal note" not in visible
    # An owner sees both.
    owner_visible = {
        c.body for c in comments_for_advisory(setup["advisory"], viewer=setup["owner"])
    }
    assert {"public feedback", "internal note"} <= owner_visible


# ---------------------------------------------------------------------------
# Timeline — the descriptive row narrates; the structured twin stays hidden
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_dismiss_advisory_timeline_shows_single_state_row(setup):
    services.dismiss_advisory(setup["advisory"], by=setup["owner"], reason="false positive")
    actions = _timeline_actions(setup["advisory"], setup["owner"])
    assert Action.ADVISORY_DISMISSED in actions
    # The structured ADVISORY_STATE_CHANGED twin is ledger-only — not on the timeline.
    assert Action.ADVISORY_STATE_CHANGED not in actions


@pytest.mark.django_db
def test_dismiss_triage_timeline_shows_single_state_row(setup):
    adv = Advisory.objects.create(
        project=setup["project"], summary="t", state=State.TRIAGE, created_by=setup["owner"]
    )
    services.dismiss_triage(adv, by=setup["owner"], reason="spam report")
    actions = _timeline_actions(adv, setup["owner"])
    assert Action.ADVISORY_DISMISSED in actions
    assert Action.ADVISORY_STATE_CHANGED not in actions


@pytest.mark.django_db
def test_promote_triage_timeline_shows_single_state_row(setup):
    adv = Advisory.objects.create(
        project=setup["project"], summary="t", state=State.TRIAGE, created_by=setup["owner"]
    )
    services.promote_triage_to_draft(adv, by=setup["owner"])
    actions = _timeline_actions(adv, setup["owner"])
    assert Action.ADVISORY_TRIAGE_PROMOTED in actions
    assert Action.ADVISORY_STATE_CHANGED not in actions


@pytest.mark.django_db
def test_review_decision_timeline_shows_single_row(setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["owner"])
    wf.approve_review(task, by=setup["admin"], notes="LGTM")
    actions = _timeline_actions(setup["advisory"], setup["owner"])
    assert Action.ADVISORY_REVIEW_APPROVED in actions
    # The structured REVIEW_TASK_STATUS_CHANGED twin is ledger-only.
    assert Action.REVIEW_TASK_STATUS_CHANGED not in actions
