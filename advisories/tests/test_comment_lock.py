"""Comment lock (dispute cool-down): owner/admin pauses new comments.

Covers the permission gate, the lock/unlock services (audit + no versioning),
the owner/admin override in ``can_comment``, and the end-to-end blocking on the
HTML comment endpoint.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from access.models import Permission as AccessPermission
from access.services import grant_to_user
from advisories import permissions as perms
from advisories import services
from advisories.models import Advisory, State
from audit.models import Action, AuditLogEntry
from comments import services as comment_services


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    owner = make_user(email="owner@example.org")
    project = make_project("acme", team_members=[owner])
    advisory = Advisory.objects.create(project=project, summary="x", state=State.DRAFT)
    return {"owner": owner, "project": project, "advisory": advisory}


# ---- Permission gate -------------------------------------------------------


@pytest.mark.django_db
def test_owner_can_lock_comments(setup):
    assert perms.can_lock_comments(setup["owner"], setup["advisory"]) is True


@pytest.mark.django_db
def test_admin_can_lock_comments(setup, make_user, admin_group):
    admin = make_user(email="admin@example.org")
    admin.groups.add(admin_group)
    assert perms.can_lock_comments(admin, setup["advisory"]) is True


@pytest.mark.django_db
def test_collaborator_and_viewer_cannot_lock_comments(setup, make_user):
    collab = make_user(email="collab@example.org")
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], collab, AccessPermission.COLLABORATOR, by=setup["owner"])
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    assert perms.can_lock_comments(collab, setup["advisory"]) is False
    assert perms.can_lock_comments(viewer, setup["advisory"]) is False


# ---- can_comment override --------------------------------------------------


@pytest.mark.django_db
def test_lock_blocks_non_owners_but_not_owner(setup, make_user):
    collab = make_user(email="collab@example.org")
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], collab, AccessPermission.COLLABORATOR, by=setup["owner"])
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    # Unlocked: everyone with access may comment.
    assert perms.can_comment(viewer, setup["advisory"]) is True

    services.lock_advisory_comments(setup["advisory"], by=setup["owner"])
    setup["advisory"].refresh_from_db()

    assert perms.can_comment(setup["owner"], setup["advisory"]) is True
    assert perms.can_comment(collab, setup["advisory"]) is False
    assert perms.can_comment(viewer, setup["advisory"]) is False


# ---- Services --------------------------------------------------------------


@pytest.mark.django_db
def test_lock_sets_fields_and_audits(setup):
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"], reason="cooling off")
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].comments_locked is True
    assert setup["advisory"].comments_locked_at is not None
    assert setup["advisory"].comments_locked_by_id == setup["owner"].pk
    assert setup["advisory"].comments_lock_reason == "cooling off"
    entry = AuditLogEntry.objects.get(
        action=Action.ADVISORY_COMMENTS_LOCKED, advisory=setup["advisory"]
    )
    assert entry.metadata["reason"] == "cooling off"


@pytest.mark.django_db
def test_unlock_clears_fields_and_audits(setup):
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"], reason="r")
    services.unlock_advisory_comments(setup["advisory"], by=setup["owner"])
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].comments_locked is False
    assert setup["advisory"].comments_locked_at is None
    assert setup["advisory"].comments_locked_by_id is None
    assert setup["advisory"].comments_lock_reason == ""
    assert AuditLogEntry.objects.filter(
        action=Action.ADVISORY_COMMENTS_UNLOCKED, advisory=setup["advisory"]
    ).exists()


@pytest.mark.django_db
def test_lock_twice_raises(setup):
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"])
    with pytest.raises(ValueError):
        services.lock_advisory_comments(setup["advisory"], by=setup["owner"])


@pytest.mark.django_db
def test_unlock_when_not_locked_raises(setup):
    with pytest.raises(ValueError):
        services.unlock_advisory_comments(setup["advisory"], by=setup["owner"])


@pytest.mark.django_db
def test_non_owner_lock_raises_permission_denied(setup, make_user):
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    with pytest.raises(PermissionDenied):
        services.lock_advisory_comments(setup["advisory"], by=viewer)


@pytest.mark.django_db
@pytest.mark.parametrize("state", [State.TRIAGE, State.DRAFT, State.PUBLISHED, State.DISMISSED])
def test_lockable_in_any_state(make_user, make_project, settings, state):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    owner = make_user(email="o@example.org")
    project = make_project("p", team_members=[owner])
    advisory = Advisory.objects.create(project=project, summary="x", state=state)
    services.lock_advisory_comments(advisory, by=owner)
    advisory.refresh_from_db()
    assert advisory.comments_locked is True


@pytest.mark.django_db
def test_lock_toggle_does_not_append_version(setup):
    before = setup["advisory"].versions.count()
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"])
    services.unlock_advisory_comments(setup["advisory"], by=setup["owner"])
    assert setup["advisory"].versions.count() == before


# ---- add_comment service enforcement ---------------------------------------


@pytest.mark.django_db
def test_add_comment_blocked_for_viewer_when_locked(setup, make_user):
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"])
    setup["advisory"].refresh_from_db()
    with pytest.raises(PermissionDenied):
        comment_services.add_comment(setup["advisory"], author=viewer, body="hi")
    # Owner override: still allowed.
    comment_services.add_comment(setup["advisory"], author=setup["owner"], body="closing note")


# ---- HTML view -------------------------------------------------------------


@pytest.mark.django_db
def test_owner_locks_via_view(client, setup):
    client.force_login(setup["owner"])
    resp = client.post(
        reverse("advisories:lock_comments", args=[setup["advisory"].advisory_id]),
        data={"reason": "dispute"},
    )
    assert resp.status_code == 302
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].comments_locked is True
    assert setup["advisory"].comments_lock_reason == "dispute"


@pytest.mark.django_db
def test_viewer_cannot_lock_via_view(client, setup, make_user):
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    client.force_login(viewer)
    resp = client.post(
        reverse("advisories:lock_comments", args=[setup["advisory"].advisory_id]),
    )
    assert resp.status_code == 403
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].comments_locked is False


@pytest.mark.django_db
def test_locked_blocks_viewer_comment_via_view_but_owner_can_post(client, setup, make_user):
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"])

    create_url = reverse("comments:create", args=[setup["advisory"].advisory_id])

    client.force_login(viewer)
    assert client.post(create_url, data={"body": "no"}).status_code == 403

    client.force_login(setup["owner"])
    assert client.post(create_url, data={"body": "closing"}).status_code == 200


@pytest.mark.django_db
def test_detail_shows_lock_button_for_owner(client, setup):
    client.force_login(setup["owner"])
    html = client.get(
        reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    ).content.decode()
    assert "Lock comments" in html


@pytest.mark.django_db
def test_detail_shows_unlock_button_when_locked(client, setup):
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"])
    client.force_login(setup["owner"])
    html = client.get(
        reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    ).content.decode()
    assert "Unlock comments" in html


@pytest.mark.django_db
def test_timeline_fragment_shows_locked_banner_and_hides_form_for_viewer(client, setup, make_user):
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"], reason="cooldown please")
    client.force_login(viewer)
    html = client.get(
        reverse("comments:timeline", args=[setup["advisory"].advisory_id])
    ).content.decode()
    assert "Comments are locked" in html
    assert "cooldown please" in html
    assert "comment-form" not in html  # no posting form for a blocked viewer


@pytest.mark.django_db
def test_unlock_restores_commenting(client, setup, make_user):
    viewer = make_user(email="viewer@example.org")
    grant_to_user(setup["advisory"], viewer, AccessPermission.VIEWER, by=setup["owner"])
    services.lock_advisory_comments(setup["advisory"], by=setup["owner"])
    services.unlock_advisory_comments(setup["advisory"], by=setup["owner"])

    client.force_login(viewer)
    resp = client.post(
        reverse("comments:create", args=[setup["advisory"].advisory_id]),
        data={"body": "back online"},
    )
    assert resp.status_code == 200
