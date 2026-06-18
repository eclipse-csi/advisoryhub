"""Authorization service for advisories.

All views, APIs, and Celery tasks resolve permission decisions through this
module. Templates may *display* using these helpers, but never *decide*.

Resolution order (highest first):

1. Anonymous → no access.
2. Member of the configured global admin/security group → owner.
3. Member of the project's security team → owner.
4. ``AdvisoryAccessGrant`` for the user (direct or via group membership) →
   highest of granted permissions (``collaborator`` or ``viewer``).
5. Otherwise → no access.

Owner is derived, never assigned: the only paths to owner are admin or
project-security-team membership. The grant model deliberately excludes
``owner`` from its choices.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Literal

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.shortcuts import get_object_or_404

from .models import Advisory, Kind, ReviewStatus, State

Permission = Literal["viewer", "collaborator", "owner"]
_RANK = {"viewer": 1, "collaborator": 2, "owner": 3}


def is_global_admin(user) -> bool:
    if not user or not getattr(user, "is_authenticated", False):
        return False
    return user.groups.filter(name=settings.OIDC_ADMIN_GROUP).exists()


def is_security_team_member(user, project) -> bool:
    if not user or not getattr(user, "is_authenticated", False):
        return False
    return user.groups.filter(pk=project.security_team_id).exists()


def is_mature_publisher_member(user, project) -> bool:
    """A user qualifies as a mature publisher iff:

    * the *project* is flagged ``is_mature_publisher``, AND
    * the user is on that project's security team.

    There used to be a parallel ``OIDC_MATURE_PUBLISHER_GROUPS`` env-list
    that could grant maturity by OIDC group membership; it's been
    removed in favour of this single source of truth on the Project
    row, so admins flip a checkbox on the project rather than syncing
    a separate env var.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if not project.is_mature_publisher:
        return False
    return is_security_team_member(user, project)


def _explicit_grant_rank(user, advisory: Advisory) -> int:
    """Highest grant rank for ``user`` (direct or via group membership)."""
    from access.models import AdvisoryAccessGrant

    user_group_ids = list(user.groups.values_list("pk", flat=True))
    grants = AdvisoryAccessGrant.objects.filter(advisory=advisory).filter(
        models_user_or_group_filter(user.pk, user_group_ids)
    )
    return max((_RANK.get(g.permission, 0) for g in grants), default=0)


def models_user_or_group_filter(user_pk: int, group_ids: list[int]):
    """Build a Q for grants matching the user directly or via a group."""
    from django.db.models import Q

    return Q(principal_type="user", principal_id=user_pk) | Q(
        principal_type="group", principal_id__in=group_ids
    )


def visible_advisories(user):
    """Advisories ``user`` may see in list views (admins see all).

    Single source of truth for list-view visibility, shared by the HTML list
    (``advisories.views.advisory_list``) and the JSON list
    (``api.views_advisories``). Matches advisories reachable via project
    security-team membership or an explicit grant (direct or via a group).
    The grant arm is a subquery — not a materialized id list — so it stays a
    single SQL statement regardless of how many grants the user holds.
    """
    from django.db.models import Q

    from access.models import AdvisoryAccessGrant

    if is_global_admin(user):
        return Advisory.objects.all()

    group_ids = list(user.groups.values_list("pk", flat=True))
    grant_subquery = AdvisoryAccessGrant.objects.filter(
        models_user_or_group_filter(user.pk, group_ids)
    ).values("advisory_id")
    return Advisory.objects.filter(
        Q(project__security_team__in=user.groups.all()) | Q(pk__in=grant_subquery)
    ).distinct()


def resolved_permission(user, advisory: Advisory) -> Permission | None:
    """Return the highest applicable permission for ``user`` on ``advisory``.

    Returns ``None`` when the user has no access at all. Publication state
    is intentionally not consulted here — visibility of published advisories
    inside AdvisoryHub requires the same explicit grant as a draft.
    """
    if is_global_admin(user):
        return "owner"
    if not user or not getattr(user, "is_authenticated", False):
        return None
    if is_security_team_member(user, advisory.project):
        return "owner"
    rank = _explicit_grant_rank(user, advisory)
    if rank >= _RANK["collaborator"]:
        return "collaborator"
    if rank >= _RANK["viewer"]:
        return "viewer"
    return None


# ---- High-level predicates --------------------------------------------------


def can_view(user, advisory: Advisory) -> bool:
    return resolved_permission(user, advisory) is not None


def can_see_user_emails(user, advisory: Advisory) -> bool:
    """Whether ``user`` may see *other* users' email addresses on this advisory.

    Owner-only (global admins + the project security team). Collaborators and
    viewers see names only — another participant's email is PII they don't need
    to do their job. A user always sees their *own* email; that exception is
    applied at the render layer (the ``user_chip`` tag), not here.
    """
    return resolved_permission(user, advisory) == "owner"


def can_comment(user, advisory: Advisory) -> bool:
    """Anyone with view access may comment — unless comments are locked.

    Triage rows were previously blocked here to keep triager-internal
    discussion away from the auto-granted reporter (viewer). That concern
    is now handled by the per-comment ``is_internal`` flag: a triager can
    discuss internally on the triage row, and the viewer sees only
    non-internal comments. See :func:`can_post_internal_comment` /
    :func:`can_see_internal_comment`.

    Comment lock (dispute cool-down): when ``advisory.comments_locked`` is set,
    only owners/admins may still post (the override that lets a maintainer add a
    closing note); collaborators and viewers are blocked. This single gate is
    consulted by the HTML view, the JSON API, the ``add_comment`` service, and
    the template's form-visibility check, so the lock lands on every write path.
    """
    perm = resolved_permission(user, advisory)
    if perm is None:
        return False
    if advisory.comments_locked:
        return perm == "owner"
    return True


def can_lock_comments(user, advisory: Advisory) -> bool:
    """Whether ``user`` may lock or unlock comments on this advisory.

    Owner-only (global admins + the project security team), in any lifecycle
    state — collaborators and viewers cannot moderate the thread. Re-checked
    server-side in :func:`advisories.services.lock_advisory_comments` /
    :func:`advisories.services.unlock_advisory_comments`.
    """
    return resolved_permission(user, advisory) == "owner"


def can_post_internal_comment(user, advisory: Advisory) -> bool:
    """Whether ``user`` may post an internal (collaborator+) comment.

    Internal comments are hidden from viewers (including the auto-granted
    reporter on a triage row), so creation is restricted to ranks that
    will also see the result. Symmetry with :func:`can_see_internal_comment`
    keeps the "you can only post what you can see" invariant.
    """
    perm = resolved_permission(user, advisory)
    return perm is not None and _RANK[perm] >= _RANK["collaborator"]


def can_see_internal_comment(user, advisory: Advisory) -> bool:
    """Whether ``user`` may see internal comments on this advisory.

    Same rank threshold as posting today. Re-checked at *read* time (and
    at notification-send time), so a collaborator demoted to viewer
    loses visibility even on comments they previously authored.
    """
    return can_post_internal_comment(user, advisory)


def can_edit(user, advisory: Advisory) -> bool:
    # Dismissed advisories are read-only for every role, admins included
    # (permissions.md §6): corrections go through reopen → edit → dismiss.
    if advisory.state == State.DISMISSED:
        return False
    perm = resolved_permission(user, advisory)
    if perm is None or _RANK[perm] < _RANK["collaborator"]:
        return False
    # Triage is owner-only. The auto-grant on submission only ever issues
    # viewer; this guard is belt-and-braces against a triager manually
    # granting collaborator on a still-untrusted intake row.
    if advisory.state == State.TRIAGE and perm != "owner":
        return False
    # Flagged for admin re-routing: locked to admins, mirroring can_triage.
    # The point of the flag is to stop non-admin owners from mutating the
    # row while it sits in the admin routing queue.
    if advisory.state == State.TRIAGE:
        intake = getattr(advisory, "intake", None)
        if intake is not None and intake.needs_admin_routing and not is_global_admin(user):
            return False
    # Frozen for review unless reopened or you're an admin.
    if advisory.review_status == ReviewStatus.SUBMITTED and not is_global_admin(user):
        return False
    return True


def can_change_project(user, advisory: Advisory, new_project) -> bool:
    """Only allowed if the user is an owner of the advisory AND a security
    team member of the *destination* project (or is a global admin)."""
    if resolved_permission(user, advisory) != "owner":
        return False
    if is_global_admin(user):
        return True
    return is_security_team_member(user, new_project)


def can_grant_access(user, advisory: Advisory) -> bool:
    return resolved_permission(user, advisory) == "owner"


def can_request_cve(user, advisory: Advisory) -> bool:
    from workflows.models import CveRequestStatus

    # CVE requests are meaningful on draft and published advisories only:
    # triage rows must be promoted first, and dismissal auto-cancels open
    # requests (permissions.md §6 — re-requesting requires a reopen).
    if advisory.state in (State.TRIAGE, State.DISMISSED):
        return False
    if resolved_permission(user, advisory) != "owner":
        return False
    if advisory.cve_requests_banned:
        return False
    if advisory.assigned_cve_id:
        return False
    return not advisory.cve_requests.filter(status=CveRequestStatus.QUEUED).exists()


def can_submit_for_review(user, advisory: Advisory) -> bool:
    # GHSA-linked advisories have no human-editable content (it's synced from
    # GitHub), so review is not applicable — see INV-GHSA-1 and the inbound-only
    # GHSA lifecycle. Refused for everyone.
    if advisory.kind == Kind.GHSA_LINKED:
        return False
    # Admins are the reviewers — they don't submit advisories for review.
    # They can publish directly (subject to the SUBMITTED gate in can_publish).
    if is_global_admin(user):
        return False
    if resolved_permission(user, advisory) != "owner":
        return False
    # State == DRAFT also excludes TRIAGE; an advisory must be promoted to
    # draft (via can_triage / promote_triage_to_draft) before review.
    if advisory.state != State.DRAFT:
        return False
    if advisory.review_status == ReviewStatus.SUBMITTED:
        return False
    return True


def can_review(user) -> bool:
    return is_global_admin(user)


def can_revoke_approval(user, advisory: Advisory) -> bool:
    """Admins can manually clear an APPROVED review status.

    Same end state as auto-invalidation on edit; the separate audit
    action distinguishes "admin retracted" from "edit drift".
    """
    if advisory.kind == Kind.GHSA_LINKED:
        return False
    if not is_global_admin(user):
        return False
    return advisory.review_status == ReviewStatus.APPROVED


def can_unassign_cve(user, advisory: Advisory) -> bool:
    # Admin-only. Project security-team members and advisory collaborators cannot
    # unassign a CVE — pulling a reserved CVE is a CNA-side operation.
    return is_global_admin(user)


def can_manage_orphan_cves(user) -> bool:
    return is_global_admin(user)


def can_dismiss(user, advisory: Advisory) -> bool:
    """Whether ``user`` can dismiss this advisory.

    Owners can dismiss any non-published advisory, *except* when a CVE is
    currently assigned — pulling the CVE is a CNA-side action that only
    admins can perform, and dismissal cascades into a CVE unassign.
    """
    if resolved_permission(user, advisory) != "owner":
        return False
    if advisory.state == State.PUBLISHED:
        return False
    if advisory.assigned_cve_id and not is_global_admin(user):
        return False
    return True


def can_reopen(user, advisory: Advisory) -> bool:
    """Whether ``user`` can reopen a dismissed advisory.

    For a dismissal that came from ``triage``/``draft``, any owner (project
    security team or global admin) may reopen — it flips straight back to the
    pre-dismissal state recorded in ``Advisory.dismissed_from_state`` and the
    normal review/publication gates re-engage. For a dismissal that came from
    ``published`` — i.e. a **withdrawal** ([INV-WITHDRAW]) — reopening is an
    *un-withdraw* that re-publishes, so it needs publish authority: a global
    admin or a mature-publisher owner (same gate as ``can_withdraw_published``).
    """
    if advisory.state != State.DISMISSED:
        return False
    if advisory.dismissed_from_state == State.PUBLISHED:
        if is_global_admin(user):
            return True
        if not is_security_team_member(user, advisory.project):
            return False
        return is_mature_publisher_member(user, advisory.project)
    return resolved_permission(user, advisory) == "owner"


def can_publish(user, advisory: Advisory) -> bool:
    if advisory.state == State.DISMISSED:
        return False
    if advisory.state == State.TRIAGE:
        return False
    # A pending review must be decided (or withdrawn) before anyone — including
    # admins — can publish. The admin is the reviewer; they should approve,
    # request changes, or reject first.
    if advisory.review_status == ReviewStatus.SUBMITTED:
        return False
    if is_global_admin(user):
        return True
    # GHSA-linked publication is system-driven: GitHub is the source of truth
    # (INV-GHSA-3), so the EF feed mirrors the GHSA automatically — auto-publish
    # when GitHub publishes, auto-re-publish when synced content changes, and
    # auto-withdraw when the GHSA goes away. Owners get no manual publish button
    # (it would be a no-op decision — refresh_for_publish only lets a publish
    # through once the GHSA is already published upstream). Admins keep a manual
    # break-glass via the earlier is_global_admin short-circuit (to re-drive a
    # stuck/failed run, or publish when GHSA_AUTO_PUBLISH_ENABLED is off); that
    # path stays GHSA-state-gated by refresh_for_publish inside publish().
    if advisory.kind == Kind.GHSA_LINKED:
        return False
    if not is_security_team_member(user, advisory.project):
        return False
    if advisory.is_mature_publisher_eligible_review_status:
        return True
    return is_mature_publisher_member(user, advisory.project)


def can_withdraw_published(user, advisory: Advisory) -> bool:
    """Whether ``user`` may withdraw a *published* advisory.

    Withdrawal re-exports the OSV/CSAF with a ``withdrawn`` marker (the doc is
    never deleted) and flips the advisory to ``dismissed``. It mirrors the
    publish authority: a global admin, or a **mature-publisher** project owner
    (who may do it even with an assigned CVE — the orphan cascade runs). A
    non-mature owner cannot withdraw directly; they request one
    (:func:`can_request_withdrawal`). Only meaningful while ``published``.
    """
    if advisory.state != State.PUBLISHED:
        return False
    if is_global_admin(user):
        return True
    if not is_security_team_member(user, advisory.project):
        return False
    return is_mature_publisher_member(user, advisory.project)


def can_request_withdrawal(user, advisory: Advisory) -> bool:
    """Whether ``user`` may *request* withdrawal of a published advisory.

    The non-mature analogue of :func:`can_withdraw_published`: a project owner who
    can't withdraw directly asks an admin to do it. Excludes admins (they withdraw
    directly) and mature-publisher owners (ditto). One request at a time.
    """
    if advisory.state != State.PUBLISHED:
        return False
    if advisory.withdrawal_requested_at is not None:
        return False
    if is_global_admin(user):
        return False
    if not is_security_team_member(user, advisory.project):
        return False
    return not is_mature_publisher_member(user, advisory.project)


def can_cancel_withdrawal_request(user, advisory: Advisory) -> bool:
    """Whether ``user`` may cancel a pending withdrawal request.

    The requesting team (project owners) may retract it, and admins may clear it.
    """
    if advisory.withdrawal_requested_at is None:
        return False
    if is_global_admin(user):
        return True
    return is_security_team_member(user, advisory.project)


def can_approve_withdrawal(user, advisory: Advisory) -> bool:
    """Whether ``user`` may approve (fulfil) a pending withdrawal request.

    Admin-only: the request was escalated *to* an admin. Approving withdraws the
    advisory using the request note as the reason.
    """
    if advisory.withdrawal_requested_at is None:
        return False
    return is_global_admin(user)


def can_withdraw_review(user, advisory: Advisory) -> bool:
    """Whether ``user`` can pull a pending review back to draft.

    The submitter's "cancel my submission" affordance — available to any
    non-admin project owner once the advisory is in ``SUBMITTED``.
    Admins are reviewers, not submitters; they decide via Approve /
    Request changes (or Dismiss if the advisory shouldn't exist).
    Withdrawing only restores ``review_status = NONE`` — it does not
    unlock publishing for non-mature-publisher projects (``can_publish``
    still requires ``APPROVED`` for them).
    """
    if advisory.kind == Kind.GHSA_LINKED:
        return False
    if is_global_admin(user):
        return False
    if resolved_permission(user, advisory) != "owner":
        return False
    return advisory.review_status == ReviewStatus.SUBMITTED


def can_create_advisory_for_project(user, project) -> bool:
    if is_global_admin(user):
        return True
    return is_security_team_member(user, project)


def can_author_any_advisory(user) -> bool:
    """Whether ``user`` may create an advisory for *at least one* project.

    The project-agnostic twin of :func:`can_create_advisory_for_project`: a
    global admin (everywhere) or a member of any project's security team. Used
    to decide whether to *offer* the "New advisory" entry point in the UI;
    actual creation is still authorized per-project at the view boundary.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if is_global_admin(user):
        return True
    from projects.models import Project

    return Project.objects.filter(security_team__in=user.groups.all()).exists()


# ---- Triage (folded from intake.permissions) -------------------------------

UNSORTED_PROJECT_SLUG = "unsorted"


def can_submit_triage_report(user) -> bool:
    """Whether ``user`` may submit a public intake report.

    Always True (including anonymous). Abuse mitigation lives in the form
    layer (honeypot + rate limit + optional captcha) and the public endpoint,
    not in authorization.
    """
    return True


def can_triage(user, advisory: Advisory) -> bool:
    """Whether ``user`` may promote/dismiss a triage advisory.

    Replaces ``intake.permissions.can_act_on_report``. Triage advisories
    flagged for admin routing are admin-only; otherwise the standard owner
    resolution (project security team or global admin) applies. GHSA-linked
    triage rows are excluded: they are a read-only mirror of GitHub's triage
    state (INV-GHSA-3) and advance automatically (triage → draft on
    acceptance, → published on publish, → dismissed on close), never by a
    human promote/dismiss decision.
    """
    if advisory.state != State.TRIAGE:
        return False
    if advisory.kind == Kind.GHSA_LINKED:
        return False
    intake = getattr(advisory, "intake", None)
    if intake is not None and intake.needs_admin_routing and not is_global_admin(user):
        return False
    return resolved_permission(user, advisory) == "owner"


def can_flag_for_admin_routing(user, advisory: Advisory) -> bool:
    """Whether ``user`` may flag a triage advisory as misrouted.

    Replaces ``intake.permissions.can_flag_for_admin_routing``. Reports
    already on the ``unsorted`` sentinel project can't be flagged as
    misrouted — that project *is* the misrouted bucket. Already-flagged
    advisories can't be re-flagged (the service would reject as a
    duplicate, but hiding the button keeps the UI honest). Admins are
    excluded because *they* are the routing destination: flagging would
    bounce work back to themselves. GHSA-linked advisories are excluded
    too: a GHSA-linked row *can* sit in triage as a read-only mirror of
    GitHub's triage state (INV-GHSA-3), but its project still follows PMI,
    never a hand-routing decision (INV-GHSA-1), so the routing flag stays
    unavailable.
    """
    if advisory.state != State.TRIAGE:
        return False
    if advisory.kind == Kind.GHSA_LINKED:
        # A GHSA-linked advisory's project follows its source repository in
        # PMI, never a human routing decision (INV-GHSA-1).
        return False
    if advisory.project.slug == UNSORTED_PROJECT_SLUG:
        return False
    intake = getattr(advisory, "intake", None)
    if intake is not None and intake.needs_admin_routing:
        return False
    if is_global_admin(user):
        return False
    return resolved_permission(user, advisory) == "owner"


def can_clear_admin_routing_flag(user, advisory: Advisory) -> bool:
    """Whether ``user`` may clear a triage advisory's routing flag.

    The reverse of :func:`can_flag_for_admin_routing`: admins AND project
    security team members may clear (broader than the flag side, which
    excludes admins because they are the routing destination).

    Advisories on the ``unsorted`` sentinel project are excluded — mirroring
    the flag side, which won't let that project be flagged. ``unsorted`` *is*
    the "needs routing" bucket ([INV-INTAKE-4], [INV-PROJECT-2]), so its flag
    can't be cleared in place: clear it by reassigning to a real project
    (``reassign_triage_project``), or by promoting / dismissing the advisory.
    Clearing in place stays available for a real project (a team retracting
    its own misrouting handoff, [INV-AUTH-6]).
    """
    if advisory.state != State.TRIAGE:
        return False
    if advisory.project.slug == UNSORTED_PROJECT_SLUG:
        return False
    return resolved_permission(user, advisory) == "owner"


def can_reassign_triage(user, advisory: Advisory) -> bool:
    """Whether ``user`` sees the in-banner "assign to project" picker on a
    flagged triage advisory (display gate).

    Admin-only, mirroring :func:`can_pick_reassignment_target` for the draft
    state. While flagged, routing decisions are admin-only ([INV-AUTH-6]) and on
    the ``unsorted`` sentinel only admins have access at all, so the picker is
    always admin-facing — it's the in-place way to resolve routing now that the
    flag can't be cleared on ``unsorted``. GHSA-linked rows are excluded: their
    project follows PMI, never a manual routing decision ([INV-GHSA-1]). The
    service (:func:`advisories.services.reassign_triage_project`) re-checks
    authority server-side.
    """
    if advisory.state != State.TRIAGE:
        return False
    if advisory.kind == Kind.GHSA_LINKED:
        return False
    return is_global_admin(user)


# ---- Draft admin-reassignment request (INV-AUTH-9) -------------------------


def can_request_reassignment(user, advisory: Advisory) -> bool:
    """Whether ``user`` may ask an admin to re-home a *draft* advisory.

    The non-locking, draft-state analogue of :func:`can_flag_for_admin_routing`:
    a project owner who finds a draft belongs to a team they're not on asks an
    admin to move it, while the team keeps editing (contrast the triage routing
    flag, which locks the row — INV-AUTH-6). Admins are excluded because *they*
    are the destination — they reassign directly rather than queue a request to
    themselves. Refused once a request is already pending (one at a time) and in
    any non-draft state. GHSA-linked advisories are refused outright: their
    project follows PMI, never a human reassignment (INV-GHSA-1).
    """
    if advisory.state != State.DRAFT:
        return False
    if advisory.kind == Kind.GHSA_LINKED:
        # A GHSA-linked advisory's project follows its source repository in
        # PMI, never a human reassignment request (INV-GHSA-1).
        return False
    if advisory.reassignment_requested_at is not None:
        return False
    if is_global_admin(user):
        return False
    return resolved_permission(user, advisory) == "owner"


def can_withdraw_reassignment_request(user, advisory: Advisory) -> bool:
    """Whether ``user`` may withdraw a pending reassignment request.

    The requesting team (project owners) may retract their own handoff, and
    admins may clear it too. Requires a request to actually be pending.
    """
    if advisory.reassignment_requested_at is None:
        return False
    if is_global_admin(user):
        return True
    return resolved_permission(user, advisory) == "owner"


def can_accept_reassignment_suggestion(user, advisory: Advisory) -> bool:
    """Whether ``user`` may one-click accept the suggested target project.

    Requires a pending request that names a suggested project. Accepting moves
    the advisory onto the target, so only someone with authority *there* may do
    it: a global admin, or a security-team member of the suggested project. The
    requester (on the *current* team, not the target) cannot accept their own
    suggestion — that's the whole point of escalating.
    """
    if advisory.reassignment_requested_at is None:
        return False
    target = advisory.reassignment_suggested_project
    if target is None:
        return False
    if is_global_admin(user):
        return True
    return is_security_team_member(user, target)


def can_resolve_reassignment(user, advisory: Advisory, new_project) -> bool:
    """Whether ``user`` may resolve a pending request by moving ``advisory`` onto
    ``new_project``.

    The server-side authority behind both the one-click accept (``new_project``
    is the suggested project) and the admin's in-banner picker (``new_project``
    is any chosen project). Like :func:`can_accept_reassignment_suggestion`,
    authority must exist *at the destination*: a global admin (any project) or a
    security-team member of ``new_project`` (a target team pulling the advisory
    over). The requester — on the *current* team, not the destination — is
    excluded.

    Equivalent to :func:`can_accept_reassignment_suggestion` when ``new_project``
    is the stored suggestion: ``request_admin_reassignment`` forbids suggesting
    the current project, so the ``new_project != current`` clause is always true
    there. That equivalence is load-bearing for the one-click tests.
    """
    if advisory.reassignment_requested_at is None:
        return False
    if new_project is None or new_project.pk == advisory.project_id:
        return False
    if is_global_admin(user):
        return True
    return is_security_team_member(user, new_project)


def can_pick_reassignment_target(user, advisory: Advisory) -> bool:
    """Whether ``user`` sees the in-banner project picker (display gate).

    Admin-only: a global admin may resolve a pending request by reassigning to
    *any* project, sparing them the full edit form. Non-admin target-team members
    keep the one-click accept (:func:`can_accept_reassignment_suggestion`); the
    requester gets neither. Server-side authority is re-checked per chosen
    project by :func:`can_resolve_reassignment`.
    """
    if advisory.reassignment_requested_at is None:
        return False
    return is_global_admin(user)


# ---- GHSA integration -------------------------------------------------------


def can_move_to_ghsa(user, advisory: Advisory) -> bool:
    """Whether ``user`` can move a native report to a GitHub Security Advisory.

    For the case where a vulnerability was filed as a native AdvisoryHub report
    (triage or draft) when it should have been a private vulnerability report on
    GitHub. Owner-only, gated on the GHSA feature, and only when the advisory's
    project has at least one active GitHub repo with private vulnerability
    reporting (PVR) enabled (cached flag — refreshed live when the picker opens,
    and re-validated server-side at move time). An assigned CVE does *not* block
    the move: GHSA-linked advisories support CVEs (the CVE-push path exists for
    exactly that), and the assigned CVE is carried onto the new GHSA.
    """
    if not getattr(settings, "GHSA_FEATURE_ENABLED", False):
        return False
    if advisory.kind != Kind.NATIVE:
        return False
    if advisory.state not in (State.TRIAGE, State.DRAFT):
        return False
    if resolved_permission(user, advisory) != "owner":
        return False
    return advisory.project.github_repositories.filter(
        soft_removed_at__isnull=True, pvr_enabled=True
    ).exists()


def can_sync_ghsa(user, advisory: Advisory) -> bool:
    """Whether ``user`` can refresh metadata for a single GHSA-linked advisory."""
    perm = resolved_permission(user, advisory)
    return perm == "owner"


def can_sync_project_ghsas(user, project) -> bool:
    """Whether ``user`` can run a project-wide GHSA sync (and PMI repo refresh)."""
    if is_global_admin(user):
        return True
    return is_security_team_member(user, project)


def can_sync_all_ghsas(user) -> bool:
    """Whether ``user`` can run an org-wide GHSA sync. Admin-only."""
    return is_global_admin(user)


def can_configure_github_app(user) -> bool:
    """Whether ``user`` can view the GitHub App configuration page."""
    return is_global_admin(user)


def can_retry_cve_push(user) -> bool:
    """Whether ``user`` can manually retry a failed CVE push to GHSA."""
    return is_global_admin(user)


# ---- Decorators / mixins ----------------------------------------------------


def require_advisory_permission(level: Permission):
    """Decorator for FBVs that takes ``advisory_id`` from the URL."""
    expected = _RANK[level]

    def deco(view):
        @wraps(view)
        def wrapper(request: HttpRequest, advisory_id: str, *args, **kwargs):
            advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
            perm = resolved_permission(request.user, advisory)
            if perm is None or _RANK[perm] < expected:
                raise PermissionDenied(f"You need {level!r} permission on this advisory.")
            return view(request, advisory, *args, **kwargs)

        return wrapper

    return deco


class AdvisoryPermissionMixin:
    """Mixin for CBVs. Set ``required_permission`` to ``viewer|collaborator|owner``."""

    required_permission: Permission = "viewer"
    # Supplied by ``django.views.generic.base.View`` at runtime; declared here so
    # the mixin type-checks standalone (it's only ever combined with a ``View``).
    kwargs: dict[str, Any]

    def get_advisory(self) -> Advisory:
        return get_object_or_404(Advisory, advisory_id=self.kwargs["advisory_id"])

    def dispatch(self, request, *args, **kwargs):
        self.advisory = self.get_advisory()
        perm = resolved_permission(request.user, self.advisory)
        if perm is None or _RANK[perm] < _RANK[self.required_permission]:
            raise PermissionDenied(
                f"You need {self.required_permission!r} permission on this advisory."
            )
        return super().dispatch(request, *args, **kwargs)
