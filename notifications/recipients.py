"""Recipient resolution for advisory notifications.

The single rule that drives this module: **filter at send time**, not at
event time. Permissions and group memberships can change between the
moment a comment/event is recorded and the moment a Celery worker picks
up the email task. We re-check ``permissions.can_view`` for every
candidate recipient when the task runs, so a user whose access was
revoked in the interim never receives the private content.

Two scopes of preference are consulted:

* The user's **global** :class:`accounts.models.NotificationPreference` —
  the default for every advisory they have access to.
* Their **per-advisory** :class:`notifications.models.AdvisoryNotificationPreference`
  override row, if one exists. Each lifecycle field there is a nullable
  boolean (``None`` = inherit the global); ``comments_level`` uses an
  empty string for the same purpose.

The ``advisory_created`` event is special: it fires only for members of
the target project's security team (not grantees), and uses *only* the
global preference — there is no per-advisory override at creation time.
"""

from __future__ import annotations

from collections.abc import Iterable

from django.conf import settings
from django.db.models import Q
from django.urls import reverse

from accounts.models import CommentLevel, NotificationPreference, User
from advisories import permissions as perms
from advisories.models import Advisory

# ---------------------------------------------------------------------------
# Candidate set construction
# ---------------------------------------------------------------------------


def candidate_users_for_advisory(advisory: Advisory) -> Iterable[User]:
    """Users who *currently* have any access to the advisory.

    The query is the union of:
      1. members of the configured global admin/security group;
      2. members of the project's security team;
      3. holders of a direct user-grant on this advisory;
      4. members of any group that holds a group-grant on this advisory.

    Each candidate is then re-checked with ``can_view`` so behaviour
    stays correct under group-membership churn.
    """
    qs = _candidate_queryset(advisory)
    return [user for user in qs if perms.can_view(user, advisory)]


def _candidate_queryset(advisory: Advisory):
    admin_group = settings.OIDC_ADMIN_GROUP
    project_team_id = advisory.project.security_team_id

    q = Q(groups__name=admin_group) | Q(groups__pk=project_team_id)

    direct_user_ids = _direct_grantee_ids(advisory)
    if direct_user_ids:
        q |= Q(pk__in=direct_user_ids)

    grantee_group_ids = _grantee_group_ids(advisory)
    if grantee_group_ids:
        q |= Q(groups__pk__in=grantee_group_ids)

    return User.objects.filter(is_active=True).filter(q).distinct()


def _direct_grantee_ids(advisory: Advisory) -> list[int]:
    try:
        from access.models import AdvisoryAccessGrant, PrincipalType
    except Exception:
        return []
    return list(
        AdvisoryAccessGrant.objects.filter(
            advisory=advisory, principal_type=PrincipalType.USER
        ).values_list("principal_id", flat=True)
    )


def _grantee_group_ids(advisory: Advisory) -> list[int]:
    try:
        from access.models import AdvisoryAccessGrant, PrincipalType
    except Exception:
        return []
    return list(
        AdvisoryAccessGrant.objects.filter(
            advisory=advisory, principal_type=PrincipalType.GROUP
        ).values_list("principal_id", flat=True)
    )


def _security_team_members(advisory: Advisory) -> Iterable[User]:
    """Members of the advisory's project security team — filtered by
    ``can_view`` to drop any stale memberships and inactive users.
    """
    team_id = advisory.project.security_team_id
    qs = User.objects.filter(is_active=True, groups__pk=team_id).distinct()
    return [u for u in qs if perms.can_view(u, advisory)]


def _roster_shadow_members(advisory: Advisory) -> list[User]:
    """Shadow (never-logged-in) security-team members of the advisory's project.

    Active roster entries (``soft_removed_at IS NULL``) whose linked user is
    still a shadow (``is_provisioned=True``, ``is_active=True``). These users
    hold no in-app access, so ``candidate_users_for_advisory`` /
    ``_security_team_members`` drop them at the ``can_view`` gate. They are
    added back explicitly — authorized by **roster membership**, not access —
    purely for notification reach (INV-NOTIFY-x). Once a member logs in they
    cease to be a shadow (``accounts.auth`` clears ``is_provisioned``) and flow
    through the normal access-backed candidate path instead, so the two sources
    never overlap.
    """
    from projects.models import SecurityTeamRosterEntry

    user_ids = SecurityTeamRosterEntry.objects.filter(
        project_id=advisory.project_id,
        soft_removed_at__isnull=True,
        user__isnull=False,
    ).values_list("user_id", flat=True)
    if not user_ids:
        return []
    return list(User.objects.filter(pk__in=user_ids, is_provisioned=True, is_active=True))


def _dedup_users(*user_lists: Iterable[User]) -> list[User]:
    """Concatenate user iterables, dropping pk duplicates, order-preserving."""
    seen: set[int] = set()
    out: list[User] = []
    for lst in user_lists:
        for user in lst:
            if user.pk not in seen:
                seen.add(user.pk)
                out.append(user)
    return out


# ---------------------------------------------------------------------------
# Preference lookup
# ---------------------------------------------------------------------------


# Maps an event name to the boolean field that controls it on both
# :class:`NotificationPreference` and
# :class:`AdvisoryNotificationPreference`.
_LIFECYCLE_EVENT_FIELDS = {
    "advisory_submitted_for_review": "on_advisory_submitted_for_review",
    "advisory_published": "on_advisory_published",
    "publication_export_status": "on_publication_export_status",
}


def get_pref(user: User) -> NotificationPreference:
    pref, _ = NotificationPreference.objects.get_or_create(user=user)
    return pref


def _override(user: User, advisory: Advisory):
    from notifications.models import AdvisoryNotificationPreference

    return AdvisoryNotificationPreference.objects.filter(user=user, advisory=advisory).first()


def resolved_comments_level(user: User, advisory: Advisory) -> str:
    """Per-advisory override → global. Empty override string = inherit."""
    global_pref = get_pref(user)
    override = _override(user, advisory)
    return (override.comments_level if override else "") or global_pref.comments_level


def resolved_lifecycle_flag(user: User, advisory: Advisory, *, field: str) -> bool:
    """Per-advisory boolean → global boolean. ``None`` override = inherit."""
    global_pref = get_pref(user)
    override = _override(user, advisory)
    if override is not None:
        value = getattr(override, field)
        if value is not None:
            return bool(value)
    return bool(getattr(global_pref, field))


# ---------------------------------------------------------------------------
# Email footer ("why am I getting this?")
# ---------------------------------------------------------------------------


def _absolute_url(path: str) -> str:
    """Prefix a site-relative path with ``ADVISORYHUB_BASE_URL`` when configured."""
    base = getattr(settings, "ADVISORYHUB_BASE_URL", "").rstrip("/")
    return f"{base}{path}" if base else path


def notification_footer(user: User, advisory: Advisory, *, kind) -> dict:
    """Per-recipient footer context for a notification email.

    Explains *why* the recipient gets this mail (their role / access), *which*
    settings govern delivery (their global default vs. an advisory-specific
    override, or the un-disableable mention floor), and *where* to change them.

    Resolution reuses :mod:`advisories.permissions` at send time, so the stated
    reason matches the authorization that actually let the email through
    (INV-AUTH-1). The dict carries only the recipient's role label, the project
    name, and ``reverse()``-built URLs — never advisory content
    (INV-SECRET-1..3).

    Never raises: a footer failure must not suppress an email (the per-task
    ``try/except`` in :mod:`notifications.tasks` would otherwise drop it), so any
    unexpected state degrades to a generic footer.

    ``kind`` is the value passed to ``_send_one`` — a plain event string for
    lifecycle mails, or a :class:`~notifications.models.NotificationKind` member
    for comment/mention/triage. Both normalise via ``getattr(kind, "value", …)``.
    """
    settings_url = _absolute_url(reverse("notifications:preferences"))
    try:
        key = getattr(kind, "value", kind)
        project_name = advisory.project.name

        # Why are they receiving this? First match wins. The mention branch is
        # gated on the kind so a security-team member still reads "member of the
        # … security team" for a *comment* mail, and "mentioned" only for a
        # *mention* mail.
        if key == "mention":
            reason = "mentioned in a comment on this advisory"
        elif perms.is_global_admin(user):
            reason = "an AdvisoryHub administrator"
        elif perms.is_security_team_member(user, advisory.project):
            reason = f"a member of the {project_name} security team"
        elif getattr(user, "is_provisioned", False):
            # Shadow roster member: notification-only reach, no ``can_view`` — so
            # it must be matched here, before ``resolved_permission`` (which
            # returns ``None`` for a shadow).
            reason = f"a member of the {project_name} security team"
        else:
            perm = perms.resolved_permission(user, advisory)
            if perm in ("collaborator", "viewer"):
                reason = f"a holder of {perm} access to this advisory"
            else:
                reason = "someone with access to this advisory"

        # Which settings govern delivery?
        if key == "mention":
            governance = "always"
        elif key == "comment":
            override = _override(user, advisory)
            governance = "advisory" if (override and override.comments_level) else "default"
        elif key in _LIFECYCLE_EVENT_FIELDS:
            override = _override(user, advisory)
            field = _LIFECYCLE_EVENT_FIELDS[key]
            governance = (
                "advisory"
                if override is not None and getattr(override, field) is not None
                else "default"
            )
        else:
            # advisory_created and triage: global preference only — no per-advisory
            # override exists for either.
            governance = "default"

        # The per-advisory panel only exists for advisories that can hold an
        # override (non-triage); only deep-link there when one actually governs.
        advisory_url = ""
        if governance == "advisory":
            advisory_url = (
                _absolute_url(reverse("advisories:detail", args=[advisory.advisory_id]))
                + "#advisory-notifications"
            )

        return {
            "footer_reason": reason,
            "footer_governance": governance,
            "footer_settings_url": settings_url,
            "footer_advisory_url": advisory_url,
        }
    except Exception:  # pragma: no cover — footer must never suppress an email
        return {
            "footer_reason": "someone with access to this advisory",
            "footer_governance": "default",
            "footer_settings_url": settings_url,
            "footer_advisory_url": "",
        }


# ---------------------------------------------------------------------------
# Per-event filtering
# ---------------------------------------------------------------------------


def filter_for_event(
    advisory: Advisory,
    *,
    event: str,
    mentioned_user_ids: list[int] | None = None,
    mentioned_group_ids: list[int] | None = None,
    internal: bool = False,
) -> list[User]:
    """Filter candidates by their notification settings for ``event``.

    ``event`` is one of:
      ``advisory_created`` (security-team only, global pref only),
      ``advisory_submitted_for_review``, ``advisory_published``,
      ``publication_export_status``, ``comment``, ``mention``.

    Active roster **shadow** members of the project (pre-provisioned,
    never-logged-in security-team members) are unioned into the candidate set
    and run through the *same* per-event gating with their default
    preferences, so they receive the same default notification set as a
    logged-in team member (INV-NOTIFY-x). The internal-comment floor below
    still drops them from internal comments (a shadow has no ``can_view``).

    ``mentioned_group_ids`` lets a ``@group`` mention of the project's security
    team reach its shadow members: a shadow is never in ``user.groups`` so it
    is never in ``mentioned_user_ids`` (which expands groups via group
    membership) — instead it is kept on the ``mention`` path when the
    advisory's ``security_team`` group id is among the mentioned groups.

    ``internal=True`` (only meaningful for ``comment``/``mention``) is the
    visibility floor: recipients who cannot see internal comments are
    dropped, even if they were @-mentioned. Mention is not allowed to
    elevate a viewer (or a shadow) past the cut.
    """
    mentioned = set(mentioned_user_ids or [])
    mentioned_groups = set(mentioned_group_ids or [])
    team_mentioned = advisory.project.security_team_id in mentioned_groups

    if event == "advisory_created":
        # Special-cased: only the project's security team is eligible (real
        # members ∪ shadow roster members), and we consult the global
        # preference exclusively. No per-advisory override applies — the user
        # has not had a chance to express one yet at creation time.
        out: list[User] = []
        for user in _dedup_users(
            _security_team_members(advisory), _roster_shadow_members(advisory)
        ):
            pref = get_pref(user)
            if pref.on_advisory_created:
                out.append(user)
        return out

    out = []
    lifecycle_field = _LIFECYCLE_EVENT_FIELDS.get(event)
    for user in _dedup_users(
        candidate_users_for_advisory(advisory), _roster_shadow_members(advisory)
    ):
        if internal and not perms.can_see_internal_comment(user, advisory):
            continue
        if lifecycle_field is not None:
            if not resolved_lifecycle_flag(user, advisory, field=lifecycle_field):
                continue
        elif event == "comment":
            level = resolved_comments_level(user, advisory)
            if level == CommentLevel.MENTIONED and user.pk not in mentioned:
                continue
        elif event == "mention":
            # Mentions are the floor — always deliver to mentioned users who
            # still have view access. A shadow is reached when the team group
            # itself was @-mentioned (it can't be in ``mentioned`` directly,
            # being absent from ``user.groups``).
            if user.pk not in mentioned and not (team_mentioned and user.is_provisioned):
                continue
        else:
            # Unknown event — be conservative and skip.
            continue
        out.append(user)
    return out
