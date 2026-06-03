"""Service-layer orchestration for the security-team roster sync.

Mirrors the shape of ``ghsa.services``: side-effect-bearing logic lives here,
the Celery wrapper in ``tasks.py`` stays thin, and ``eclipse_api.py`` only
fetches (no DB writes). Every external-system call funnels its error through
``audit.services.redact_secrets`` so a leaked OAuth token never lands in the
audit table or the project's ``last_roster_sync_error`` banner.

The roster sync pre-provisions **shadow** users so members of a project's
Eclipse security team are reachable by notification before they ever log in.
A shadow user holds NO authorization (it is not a member of any group); its
only effect is notification reach (see ``notifications.recipients`` and
INV-OIDC-5 / INV-NOTIFY-x). On first OIDC login the existing email fallback in
``accounts.auth`` links the member to their shadow row and clears
``is_provisioned``; from then on their access is governed by the OIDC claim.
"""

from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from accounts.models import User
from audit.models import Action
from audit.services import record, redact_secrets

from .eclipse_api import EclipseApiError, fetch_account_email, fetch_project_members
from .models import Project, SecurityTeamRosterEntry

logger = logging.getLogger(__name__)

# The sentinel project for unrouted triage advisories is not a real PMI
# project (its ``security_team`` is the admin group), so it has no roster to
# sync. Kept in sync with ``advisories.permissions.UNSORTED_PROJECT_SLUG``.
UNSORTED_PROJECT_SLUG = "unsorted"


def _provision_or_link_shadow(*, email: str, display_name: str) -> tuple[User, bool]:
    """Return the ``User`` for ``email``, creating a shadow account if needed.

    Reuses any existing user (shadow *or* real) with that email — never
    creates a duplicate, and never overrides an already-logged-in account.
    Returns ``(user, created)`` where ``created`` is True only when a brand-new
    shadow user was minted. A freshly created shadow has an unusable password,
    ``is_provisioned=True`` and **no** group membership.
    """
    existing = User.objects.filter(email__iexact=email).first()
    if existing is not None:
        # Backfill a blank display_name on a shadow row, but never touch a
        # real (already-logged-in) user's profile from PMI data.
        if existing.is_provisioned and display_name and not existing.display_name:
            existing.display_name = display_name
            existing.save(update_fields=["display_name"])
        return existing, False
    user = User.objects.create_user(
        email=email,
        display_name=display_name or "",
        is_provisioned=True,
    )
    return user, True


@transaction.atomic
def sync_security_team_roster(project: Project, *, by) -> int:
    """Mirror ``project``'s Eclipse security-team roster into the local table.

    Returns the number of *active* roster rows after the sync. Rows whose
    member disappears from PMI are soft-removed; reappearing members are
    reactivated. Members whose email can't be resolved this run are kept (not
    soft-removed) and retried next run — a transient email-lookup failure must
    not drop a still-present member.

    Eclipse API failures don't raise: they're recorded on the project (so the
    project page can surface a "stale" banner) and retried on the next beat
    tick — same contract as ``ghsa.services.sync_project_repos_from_pmi``.
    """
    now = timezone.now()
    try:
        members = fetch_project_members(project.slug)
    except EclipseApiError as exc:
        project.last_roster_sync_error = redact_secrets(str(exc))[:8000]
        project.save(update_fields=["last_roster_sync_error"])
        record(
            action=Action.SECURITY_ROSTER_SYNCED,
            actor=by,
            metadata={"project_slug": project.slug, "status": "failed"},
            new_value={"error": project.last_roster_sync_error},
        )
        logger.warning(
            "Roster sync failed for %s: %s", project.slug, project.last_roster_sync_error
        )
        return project.security_roster.filter(soft_removed_at__isnull=True).count()

    existing = {r.eclipse_username: r for r in project.security_roster.all()}
    seen: set[str] = set()
    roster_created = 0
    roster_reactivated = 0
    shadow_users_created = 0

    for member in members:
        username = member["username"]
        # On PMI ⇒ never soft-remove for an email blip, regardless of outcome.
        seen.add(username)
        row = existing.get(username)
        try:
            email = fetch_account_email(username)
        except EclipseApiError as exc:
            email = None
            logger.warning(
                "Email lookup failed for %s/%s: %s",
                project.slug,
                username,
                redact_secrets(str(exc)),
            )
        if not email:
            # Can't (re)provision without an email; just keep an existing row
            # alive (reactivating if it had been soft-removed) and move on.
            if row is not None:
                row.last_seen_in_pmi_at = now
                fields = ["last_seen_in_pmi_at"]
                if row.soft_removed_at is not None:
                    row.soft_removed_at = None
                    fields.append("soft_removed_at")
                    roster_reactivated += 1
                row.save(update_fields=fields)
            continue

        user, created = _provision_or_link_shadow(email=email, display_name=member.get("name", ""))
        if created:
            shadow_users_created += 1
        if row is None:
            SecurityTeamRosterEntry.objects.create(
                project=project,
                eclipse_username=username,
                email=email,
                display_name=member.get("name", ""),
                user=user,
                last_seen_in_pmi_at=now,
            )
            roster_created += 1
        else:
            row.email = email
            row.display_name = member.get("name", "") or row.display_name
            row.user = user
            row.last_seen_in_pmi_at = now
            reactivated = row.soft_removed_at is not None
            row.soft_removed_at = None
            row.save(
                update_fields=[
                    "email",
                    "display_name",
                    "user",
                    "last_seen_in_pmi_at",
                    "soft_removed_at",
                ]
            )
            if reactivated:
                roster_reactivated += 1

    # Anything previously known but absent now → soft-remove (idempotent).
    # NB: this never de-authorizes a member who already logged in — their
    # access is OIDC-claim-driven, independent of the roster (INV-OIDC-5).
    roster_removed = 0
    for username, row in existing.items():
        if username not in seen and row.soft_removed_at is None:
            row.soft_removed_at = now
            row.save(update_fields=["soft_removed_at"])
            roster_removed += 1

    project.last_roster_sync_at = now
    project.last_roster_sync_error = ""
    project.save(update_fields=["last_roster_sync_at", "last_roster_sync_error"])

    active = project.security_roster.filter(soft_removed_at__isnull=True).count()
    record(
        action=Action.SECURITY_ROSTER_SYNCED,
        actor=by,
        metadata={
            "project_slug": project.slug,
            "status": "succeeded",
            "members": len(members),
            "active": active,
            "roster_created": roster_created,
            "roster_reactivated": roster_reactivated,
            "roster_removed": roster_removed,
            "shadow_users_created": shadow_users_created,
        },
    )
    return active


def sync_all_security_team_rosters(*, by) -> dict:
    """Sync every real project's roster. Returns ``{refreshed, failed}``.

    Each project syncs in its own transaction (``sync_security_team_roster`` is
    atomic), so one project's failure never rolls back another's. The unrouted
    ``unsorted`` sentinel project is skipped — it has no PMI roster.
    """
    refreshed = 0
    failed = 0
    for project in Project.objects.exclude(slug=UNSORTED_PROJECT_SLUG):
        try:
            sync_security_team_roster(project, by=by)
            refreshed += 1
        except Exception:  # pragma: no cover — defensive; failures are recorded inline
            failed += 1
            logger.exception("Roster sync raised for %s", project.slug)
    return {"refreshed": refreshed, "failed": failed}
