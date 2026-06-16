"""Triage state lifecycle tests.

Covers permissions, services, and HTMX views for ``state=TRIAGE``
advisories. The legacy ``intake/tests/test_triage*`` coverage was folded
in here when ``intake.VulnerabilityReport`` was retired in favour of
``Advisory(state=triage)`` + ``AdvisoryIntakeMetadata``.
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from access.models import AdvisoryAccessGrant
from advisories import permissions as perms
from advisories import services
from advisories.models import Advisory, AdvisoryIntakeMetadata, Kind, State
from projects.models import Project


@pytest.fixture
def unsorted_project(db, admin_group):
    project, _ = Project.objects.get_or_create(
        slug="unsorted",
        defaults={
            "name": "Unsorted reports",
            "security_team": admin_group,
            "is_mature_publisher": False,
        },
    )
    return project


@pytest.fixture
def admin_user(db, make_user, admin_group):
    return make_user(email="admin@example.org", groups=[admin_group.name])


def _make_triage_advisory(project, *, reporter_user=None, display_name="", flagged=False):
    """Create an Advisory(state=TRIAGE) + sidecar directly, skipping the
    service so tests can construct arbitrary triage states."""
    adv = Advisory.objects.create(
        project=project,
        state=State.TRIAGE,
        summary="A vulnerability",
        details="Some details.",
        created_by=reporter_user,
    )
    AdvisoryIntakeMetadata.objects.create(
        advisory=adv,
        reporter_user=reporter_user,
        reporter_display_name=display_name,
        needs_admin_routing=flagged,
        admin_routing_note="flagged" if flagged else "",
    )
    return adv


# -------------------- Permission predicates --------------------------------


def test_can_view_in_triage_for_security_team(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    assert perms.can_view(member, adv) is True


def test_can_view_in_triage_for_grantee(db, make_user, make_project):
    project = make_project("alpha")
    grantee = make_user(email="g@example.org")
    adv = _make_triage_advisory(project)
    AdvisoryAccessGrant.objects.create(
        advisory=adv,
        principal_type="user",
        principal_id=grantee.pk,
        permission="viewer",
    )
    assert perms.can_view(grantee, adv) is True


def test_can_comment_allowed_in_triage(db, make_user, make_project):
    """Triage rows now accept comments (the original block was lifted in
    favour of the per-comment ``is_internal`` flag — triagers post
    internal, the reporter sees only public).
    """
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    assert perms.can_comment(member, adv) is True
    # Owner-rank can post internal; viewer cannot.
    assert perms.can_post_internal_comment(member, adv) is True

    grantee = make_user(email="g@example.org")
    AdvisoryAccessGrant.objects.create(
        advisory=adv,
        principal_type="user",
        principal_id=grantee.pk,
        permission="viewer",
    )
    assert perms.can_comment(grantee, adv) is True
    assert perms.can_post_internal_comment(grantee, adv) is False
    assert perms.can_see_internal_comment(grantee, adv) is False


def test_can_edit_triage_owner_only(db, make_user, make_project):
    project = make_project("alpha")
    owner = make_user(email="o@example.org", groups=[f"{project.slug}-security"])
    collaborator = make_user(email="c@example.org")
    adv = _make_triage_advisory(project)
    AdvisoryAccessGrant.objects.create(
        advisory=adv,
        principal_type="user",
        principal_id=collaborator.pk,
        permission="collaborator",
    )
    assert perms.can_edit(owner, adv) is True
    # Belt-and-braces: a hypothetical collaborator grant doesn't activate
    # edit in TRIAGE state.
    assert perms.can_edit(collaborator, adv) is False


def test_can_publish_forbidden_in_triage(db, admin_user, make_project):
    project = make_project("alpha")
    adv = _make_triage_advisory(project)
    assert perms.can_publish(admin_user, adv) is False


def test_can_request_cve_forbidden_in_triage(db, admin_user, make_project):
    project = make_project("alpha")
    adv = _make_triage_advisory(project)
    assert perms.can_request_cve(admin_user, adv) is False


def test_can_triage_owner(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    assert perms.can_triage(member, adv) is True


def test_can_triage_flagged_advisory_admin_only(db, make_user, make_project, admin_user):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project, flagged=True)
    assert perms.can_triage(member, adv) is False
    assert perms.can_triage(admin_user, adv) is True


def test_can_triage_only_in_triage_state(db, admin_user, make_project):
    project = make_project("alpha")
    adv = Advisory.objects.create(project=project, state=State.DRAFT, summary="d", details="")
    assert perms.can_triage(admin_user, adv) is False


def test_can_flag_for_admin_routing_excludes_unsorted(
    db, make_user, make_project, unsorted_project
):
    member = make_user(email="m@example.org", groups=[unsorted_project.security_team.name])
    adv = _make_triage_advisory(unsorted_project)
    assert perms.can_flag_for_admin_routing(member, adv) is False


def test_can_flag_for_admin_routing_team_member(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    assert perms.can_flag_for_admin_routing(member, adv) is True


def test_can_flag_for_admin_routing_already_flagged(db, make_user, make_project):
    """Once flagged, the same owner can't re-flag — the button hides
    itself and the service would raise ``already flagged`` anyway."""
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project, flagged=True)
    assert perms.can_flag_for_admin_routing(member, adv) is False


def _make_ghsa_triage_advisory(project):
    """A GHSA-linked advisory mirrored in triage (read-only, INV-GHSA-3)."""
    return Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        ghsa_owner="eclipse",
        ghsa_repo="widget",
        state=State.TRIAGE,
        summary="A vulnerability",
    )


def test_can_flag_for_admin_routing_excludes_ghsa_linked(db, make_user, make_project):
    """A GHSA-linked advisory's project follows PMI, never a routing decision
    (INV-GHSA-1) — even though it can now sit in triage as a read-only GitHub
    mirror (INV-GHSA-3)."""
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_ghsa_triage_advisory(project)
    assert perms.can_flag_for_admin_routing(member, adv) is False


def test_can_triage_excludes_ghsa_linked(db, make_user, make_project, admin_user):
    """A GHSA-linked triage row is a read-only mirror of GitHub (INV-GHSA-3): no
    human promote/dismiss-via-triage, for owners or admins."""
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_ghsa_triage_advisory(project)
    assert perms.can_triage(member, adv) is False
    assert perms.can_triage(admin_user, adv) is False


def test_can_reassign_triage_admin(db, admin_user, make_project):
    project = make_project("alpha")
    adv = _make_triage_advisory(project, flagged=True)
    assert perms.can_reassign_triage(admin_user, adv) is True


def test_can_reassign_triage_denies_non_admin_owner(db, make_user, make_project):
    """The in-banner picker is admin-only: routing while flagged is admin-only
    (INV-AUTH-6), even for the project's own security team."""
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project, flagged=True)
    assert perms.can_reassign_triage(member, adv) is False


def test_can_reassign_triage_excludes_ghsa_linked(db, admin_user, make_project):
    """GHSA-linked rows follow PMI, never manual routing (INV-GHSA-1)."""
    project = make_project("alpha")
    adv = _make_ghsa_triage_advisory(project)
    assert perms.can_reassign_triage(admin_user, adv) is False


def test_can_reassign_triage_only_in_triage_state(db, admin_user, make_project):
    project = make_project("alpha")
    adv = Advisory.objects.create(project=project, state=State.DRAFT, summary="d", details="")
    assert perms.can_reassign_triage(admin_user, adv) is False


# -------------------- Services --------------------------------------------


def test_promote_triage_to_draft(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    promoted = services.promote_triage_to_draft(adv, by=member)
    assert promoted.state == State.DRAFT
    # Comments open up after promotion:
    assert perms.can_comment(member, promoted) is True


def test_promote_requires_explicit_project_for_unsorted(
    db, admin_user, make_project, unsorted_project
):
    target = make_project("alpha")
    adv = _make_triage_advisory(unsorted_project)
    with pytest.raises(ValueError):
        services.promote_triage_to_draft(adv, by=admin_user)
    # With explicit target it succeeds:
    promoted = services.promote_triage_to_draft(adv, by=admin_user, project=target)
    assert promoted.state == State.DRAFT
    assert promoted.project == target


def test_promote_clears_admin_routing_flag(db, admin_user, make_project):
    project = make_project("alpha")
    adv = _make_triage_advisory(project, flagged=True)
    services.promote_triage_to_draft(adv, by=admin_user)
    adv.intake.refresh_from_db()
    assert adv.intake.needs_admin_routing is False


def test_dismiss_triage(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    dismissed = services.dismiss_triage(adv, by=member, reason="spam")
    assert dismissed.state == State.DISMISSED
    assert dismissed.dismissed_reason == "spam"


def test_dismiss_requires_reason(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    with pytest.raises(ValueError):
        services.dismiss_triage(adv, by=member, reason="")


def test_flag_for_admin_routing(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    services.flag_for_admin_routing(adv, by=member, note="goes to bravo")
    adv.intake.refresh_from_db()
    assert adv.intake.needs_admin_routing is True
    assert adv.intake.admin_routing_note == "goes to bravo"


def test_flag_requires_note(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    with pytest.raises(ValueError):
        services.flag_for_admin_routing(adv, by=member, note="")


def test_clear_admin_routing_flag(db, admin_user, make_project):
    project = make_project("alpha")
    adv = _make_triage_advisory(project, flagged=True)
    services.clear_admin_routing_flag(adv, by=admin_user, note="routed correctly")
    adv.intake.refresh_from_db()
    assert adv.intake.needs_admin_routing is False
    assert adv.intake.admin_routing_note == ""
    assert adv.intake.flagged_for_routing_at is None
    assert adv.intake.flagged_for_routing_by is None


def test_clear_routing_flag_permission_admin(db, admin_user, make_project):
    project = make_project("alpha")
    adv = _make_triage_advisory(project, flagged=True)
    assert perms.can_clear_admin_routing_flag(admin_user, adv) is True


def test_clear_routing_flag_permission_team_member(db, make_user, make_project):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project, flagged=True)
    assert perms.can_clear_admin_routing_flag(member, adv) is True
    # Team member can also actually invoke the service end-to-end.
    services.clear_admin_routing_flag(adv, by=member)
    adv.intake.refresh_from_db()
    assert adv.intake.needs_admin_routing is False


def test_clear_routing_flag_permission_denied_for_outsider(db, make_user, make_project):
    project = make_project("alpha")
    outsider = make_user(email="o@example.org")
    adv = _make_triage_advisory(project, flagged=True)
    assert perms.can_clear_admin_routing_flag(outsider, adv) is False
    from django.core.exceptions import PermissionDenied

    with pytest.raises(PermissionDenied):
        services.clear_admin_routing_flag(adv, by=outsider)


def test_clear_routing_flag_excludes_unsorted(db, admin_user, unsorted_project):
    """The flag on an ``unsorted`` advisory can't be cleared in place — not
    even by an admin. ``unsorted`` *is* the needs-routing bucket
    (INV-INTAKE-4); the only way off the flag is reassigning to a real project
    (or promoting / dismissing). Mirrors the flag side's unsorted exclusion."""
    from django.core.exceptions import PermissionDenied

    adv = _make_triage_advisory(unsorted_project, flagged=True)
    assert perms.can_clear_admin_routing_flag(admin_user, adv) is False
    with pytest.raises(PermissionDenied):
        services.clear_admin_routing_flag(adv, by=admin_user)
    adv.intake.refresh_from_db()
    assert adv.intake.needs_admin_routing is True


def test_clear_routing_flag_requires_flagged_state(db, admin_user, make_project):
    project = make_project("alpha")
    adv = _make_triage_advisory(project, flagged=False)
    with pytest.raises(ValueError):
        services.clear_admin_routing_flag(adv, by=admin_user)


def test_clear_routing_flag_requires_triage_state(db, admin_user, make_project):
    """Clearing a flag on a non-triage advisory is rejected.

    The permission predicate already gates on state==TRIAGE, so we get
    PermissionDenied before the in-service ValueError fires — same pattern
    as flag_for_admin_routing / promote_triage_to_draft.
    """
    from django.core.exceptions import PermissionDenied

    project = make_project("alpha")
    adv = _make_triage_advisory(project, flagged=True)
    # Promote first (which itself clears the flag); re-flag the sidecar
    # directly to simulate "flag set on a now non-triage advisory" (impossible
    # in practice, but the guard should still fire defensively).
    services.promote_triage_to_draft(adv, by=admin_user)
    adv.intake.refresh_from_db()
    adv.intake.needs_admin_routing = True
    adv.intake.save(update_fields=["needs_admin_routing"])
    with pytest.raises(PermissionDenied):
        services.clear_admin_routing_flag(adv, by=admin_user)


def test_clear_routing_flag_emits_audit(db, admin_user, make_project):
    from audit.models import Action, AuditLogEntry

    project = make_project("alpha")
    adv = _make_triage_advisory(project, flagged=True)
    adv.intake.admin_routing_note = "really belongs to bravo"
    adv.intake.save(update_fields=["admin_routing_note"])
    services.clear_admin_routing_flag(adv, by=admin_user, note="routed correctly")
    entry = AuditLogEntry.objects.filter(
        advisory=adv, action=Action.ADVISORY_ROUTING_FLAG_CLEARED
    ).get()
    assert entry.actor == admin_user
    assert entry.metadata["previous_note"] == "really belongs to bravo"
    assert entry.metadata["note"] == "routed correctly"


def test_flagged_triage_advisory_is_not_editable_by_team_member(db, make_user, make_project):
    """Per design: while a triage advisory sits in the admin routing queue,
    the project owner shouldn't be able to mutate the form content."""
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project, flagged=True)
    assert perms.can_edit(member, adv) is False


def test_flagged_triage_advisory_remains_editable_by_admin(db, admin_user, make_project):
    project = make_project("alpha")
    adv = _make_triage_advisory(project, flagged=True)
    assert perms.can_edit(admin_user, adv) is True


def test_reassign_triage_project_admin(db, admin_user, make_project):
    src = make_project("alpha")
    dst = make_project("bravo")
    adv = _make_triage_advisory(src)
    services.reassign_triage_project(adv, by=admin_user, new_project=dst)
    adv.refresh_from_db()
    assert adv.project == dst
    assert adv.state == State.TRIAGE  # state preserved


def test_reassign_triage_project_team_member_cross_team_denied(db, make_user, make_project):
    src = make_project("alpha")
    dst = make_project("bravo")
    src_member = make_user(email="m@example.org", groups=[f"{src.slug}-security"])
    adv = _make_triage_advisory(src)
    from django.core.exceptions import PermissionDenied

    with pytest.raises(PermissionDenied):
        services.reassign_triage_project(adv, by=src_member, new_project=dst)


def test_reassign_triage_off_unsorted_clears_flag(db, admin_user, make_project, unsorted_project):
    """Re-routing an ``unsorted`` advisory to a real project resolves the
    routing question — the admin-routing flag is cleared as a side effect."""
    dst = make_project("alpha")
    adv = _make_triage_advisory(unsorted_project, flagged=True)
    services.reassign_triage_project(adv, by=admin_user, new_project=dst)
    adv.refresh_from_db()
    adv.intake.refresh_from_db()
    assert adv.project == dst
    assert adv.intake.needs_admin_routing is False


def test_reassign_triage_onto_unsorted_sets_flag(db, admin_user, make_project, unsorted_project):
    """Parking an advisory on the routing sentinel (re)raises the flag rather
    than clearing it: anything on ``unsorted`` needs routing (INV-INTAKE-4)."""
    src = make_project("alpha")
    adv = _make_triage_advisory(src, flagged=False)
    services.reassign_triage_project(adv, by=admin_user, new_project=unsorted_project)
    adv.refresh_from_db()
    adv.intake.refresh_from_db()
    assert adv.project == unsorted_project
    assert adv.intake.needs_admin_routing is True
    assert adv.intake.admin_routing_note != ""
    assert adv.intake.flagged_for_routing_by == admin_user


# -------------------- Views -----------------------------------------------


def test_triage_list_admin(db, admin_user, make_project, client):
    """Admin sees every triage row through the standard advisory list."""
    p1 = make_project("alpha")
    p2 = make_project("bravo")
    _make_triage_advisory(p1)
    _make_triage_advisory(p2)
    client.force_login(admin_user)
    resp = client.get(reverse("advisories:list"), {"state": State.TRIAGE.value})
    assert resp.status_code == 200
    advisories = list(resp.context["advisories"])
    assert len(advisories) == 2


def test_triage_list_team_member_only_own_projects(db, make_user, make_project, client):
    """Team member's triage list view only includes their own project's rows."""
    p1 = make_project("alpha")
    p2 = make_project("bravo")
    _make_triage_advisory(p1)
    _make_triage_advisory(p2)
    member = make_user(email="m@example.org", groups=[f"{p1.slug}-security"])
    client.force_login(member)
    resp = client.get(reverse("advisories:list"), {"state": State.TRIAGE.value})
    assert resp.status_code == 200
    advisories = list(resp.context["advisories"])
    assert len(advisories) == 1
    assert advisories[0].project == p1


def test_triage_detail(db, make_user, make_project, client):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    client.force_login(member)
    resp = client.get(reverse("advisories:detail", args=[adv.advisory_id]))
    assert resp.status_code == 200
    assert resp.context["advisory"] == adv
    assert resp.context["is_triage"] is True
    assert resp.context["can_triage"] is True


def test_triage_promote_view(db, make_user, make_project, client):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    client.force_login(member)
    resp = client.post(
        reverse("advisories:promote", args=[adv.advisory_id]),
        data={},
    )
    # Redirects to the promoted advisory detail.
    assert resp.status_code == 302
    adv.refresh_from_db()
    assert adv.state == State.DRAFT


def test_triage_dismiss_view(db, make_user, make_project, client):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    client.force_login(member)
    resp = client.post(
        reverse("advisories:dismiss", args=[adv.advisory_id]),
        data={"reason": "spam"},
    )
    assert resp.status_code == 302
    adv.refresh_from_db()
    assert adv.state == State.DISMISSED


def test_triage_flag_view(db, make_user, make_project, client):
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project)
    client.force_login(member)
    resp = client.post(
        reverse("advisories:flag", args=[adv.advisory_id]),
        data={"note": "goes to bravo"},
    )
    assert resp.status_code == 302
    adv.intake.refresh_from_db()
    assert adv.intake.needs_admin_routing is True


def test_triage_clear_routing_flag_view(db, admin_user, make_project, client):
    project = make_project("alpha")
    adv = _make_triage_advisory(project, flagged=True)
    client.force_login(admin_user)
    resp = client.post(
        reverse("advisories:clear_routing_flag", args=[adv.advisory_id]),
        data={"note": "routed correctly"},
    )
    assert resp.status_code == 302
    adv.intake.refresh_from_db()
    assert adv.intake.needs_admin_routing is False


def test_triage_clear_routing_flag_view_denies_outsider(db, make_user, make_project, client):
    project = make_project("alpha")
    outsider = make_user(email="o@example.org")
    adv = _make_triage_advisory(project, flagged=True)
    client.force_login(outsider)
    resp = client.post(
        reverse("advisories:clear_routing_flag", args=[adv.advisory_id]),
    )
    assert resp.status_code == 403
    adv.intake.refresh_from_db()
    assert adv.intake.needs_admin_routing is True


def test_triage_clear_routing_flag_view_denied_on_unsorted(
    db, admin_user, unsorted_project, client
):
    """A forced POST to clear the flag on an ``unsorted`` advisory is rejected
    even for an admin — the button is hidden, so this only happens by hand."""
    adv = _make_triage_advisory(unsorted_project, flagged=True)
    client.force_login(admin_user)
    resp = client.post(reverse("advisories:clear_routing_flag", args=[adv.advisory_id]))
    assert resp.status_code == 403
    adv.intake.refresh_from_db()
    assert adv.intake.needs_admin_routing is True


def test_triage_edit_view_denies_team_member_when_flagged(db, make_user, make_project, client):
    """Belt-and-braces view-level check for the can_edit lockdown."""
    project = make_project("alpha")
    member = make_user(email="m@example.org", groups=[f"{project.slug}-security"])
    adv = _make_triage_advisory(project, flagged=True)
    client.force_login(member)
    resp = client.get(reverse("advisories:edit", args=[adv.advisory_id]))
    assert resp.status_code == 403


def test_triage_reassign_view_clears_flag_and_moves(
    db, admin_user, make_project, unsorted_project, client
):
    """The in-banner picker assigns an unsorted advisory to a real project and
    clears the routing flag as a side effect."""
    dst = make_project("alpha")
    adv = _make_triage_advisory(unsorted_project, flagged=True)
    client.force_login(admin_user)
    resp = client.post(
        reverse("advisories:reassign_triage", args=[adv.advisory_id]),
        data={"project_slug": dst.slug},
    )
    assert resp.status_code == 302
    adv.refresh_from_db()
    adv.intake.refresh_from_db()
    assert adv.project == dst
    assert adv.intake.needs_admin_routing is False


def test_triage_reassign_view_requires_project(db, admin_user, unsorted_project, client):
    adv = _make_triage_advisory(unsorted_project, flagged=True)
    client.force_login(admin_user)
    resp = client.post(reverse("advisories:reassign_triage", args=[adv.advisory_id]), data={})
    assert resp.status_code == 400
    adv.refresh_from_db()
    assert adv.project == unsorted_project  # unchanged


def test_triage_reassign_view_denies_non_admin(
    db, make_user, make_project, unsorted_project, client
):
    """A non-admin can't reassign a flagged advisory — the service raises
    PermissionDenied (403); the picker is hidden from them anyway."""
    dst = make_project("alpha")
    outsider = make_user(email="o@example.org")
    adv = _make_triage_advisory(unsorted_project, flagged=True)
    client.force_login(outsider)
    resp = client.post(
        reverse("advisories:reassign_triage", args=[adv.advisory_id]),
        data={"project_slug": dst.slug},
    )
    assert resp.status_code == 403
    adv.refresh_from_db()
    assert adv.project == unsorted_project


def test_triage_routing_banner_unsorted_shows_picker_not_clear(
    db, admin_user, unsorted_project, client
):
    """On `unsorted`, the admin sees the assign-to-project picker and NOT the
    in-place 'Clear flag' control."""
    adv = _make_triage_advisory(unsorted_project, flagged=True)
    client.force_login(admin_user)
    resp = client.get(reverse("advisories:detail", args=[adv.advisory_id]))
    assert resp.status_code == 200
    assert resp.context["can_reassign_triage"] is True
    assert resp.context["can_clear_routing"] is False
    body = resp.content.decode()
    assert reverse("advisories:reassign_triage", args=[adv.advisory_id]) in body
    assert reverse("advisories:clear_routing_flag", args=[adv.advisory_id]) not in body


def test_triage_routing_banner_admin_sees_both_on_real_project(
    db, admin_user, make_project, client
):
    """On a real-project flagged advisory, the admin sees BOTH assign-to-project
    and clear-flag controls."""
    project = make_project("alpha")
    adv = _make_triage_advisory(project, flagged=True)
    client.force_login(admin_user)
    resp = client.get(reverse("advisories:detail", args=[adv.advisory_id]))
    assert resp.context["can_reassign_triage"] is True
    assert resp.context["can_clear_routing"] is True


def test_triage_detail_403_for_outsider(db, make_user, make_project, client):
    project = make_project("alpha")
    outsider = make_user(email="o@example.org")
    adv = _make_triage_advisory(project)
    client.force_login(outsider)
    resp = client.get(reverse("advisories:detail", args=[adv.advisory_id]))
    assert resp.status_code == 403
