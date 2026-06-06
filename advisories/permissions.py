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

from .models import Advisory, ReviewStatus, State

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
    """Anyone with view access may comment.

    Triage rows were previously blocked here to keep triager-internal
    discussion away from the auto-granted reporter (viewer). That concern
    is now handled by the per-comment ``is_internal`` flag: a triager can
    discuss internally on the triage row, and the viewer sees only
    public comments. See :func:`can_post_internal_comment` /
    :func:`can_see_internal_comment`.
    """
    return resolved_permission(user, advisory) is not None


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

    if advisory.state == State.TRIAGE:
        return False
    if resolved_permission(user, advisory) != "owner":
        return False
    if advisory.cve_requests_banned:
        return False
    if advisory.assigned_cve_id:
        return False
    return not advisory.cve_requests.filter(status=CveRequestStatus.QUEUED).exists()


def can_submit_for_review(user, advisory: Advisory) -> bool:
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

    Owners (project security team or global admin) only. Reopen flips state
    back to the pre-dismissal value (``triage`` or ``draft``) recorded in
    ``Advisory.dismissed_from_state``; the normal publication/review gates
    re-engage on the way back out. There is no published→reopen path —
    dismissed advisories never originated from ``published`` (the lifecycle
    forbids ``published → dismissed``).
    """
    if advisory.state != State.DISMISSED:
        return False
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
    if not is_security_team_member(user, advisory.project):
        return False
    if advisory.is_mature_publisher_eligible_review_status:
        return True
    return is_mature_publisher_member(user, advisory.project)


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
    if is_global_admin(user):
        return False
    if resolved_permission(user, advisory) != "owner":
        return False
    return advisory.review_status == ReviewStatus.SUBMITTED


def can_create_advisory_for_project(user, project) -> bool:
    if is_global_admin(user):
        return True
    return is_security_team_member(user, project)


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
    resolution (project security team or global admin) applies.
    """
    if advisory.state != State.TRIAGE:
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
    bounce work back to themselves.
    """
    if advisory.state != State.TRIAGE:
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
    """
    if advisory.state != State.TRIAGE:
        return False
    return resolved_permission(user, advisory) == "owner"


# ---- GHSA integration -------------------------------------------------------


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
