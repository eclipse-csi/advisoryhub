"""GDPR forgetting + audit retention helpers.

Two operations that intentionally bypass the append-only triggers on
``audit_auditlogentry``:

* :func:`forget_user` — when a user exercises a right-to-be-forgotten,
  anonymize their identity everywhere it might still surface (audit log
  JSON fields, their authored comments, pending invitations they created).
  The audit log itself stays — we only scrub *personal* fields, leaving
  the action history intact.
* :func:`prune_audit_older_than` — drop audit log entries older than the
  configured retention horizon.

Both functions use :func:`_audit_trigger_bypass` to temporarily lower
``session_replication_role`` to ``replica`` for the duration of the
transaction, which is the supported Postgres way to disable
non-replication triggers without dropping them.

The escape hatch only applies inside the function's ``with`` block; once
control leaves it, normal append-only enforcement is back. Each call
emits an audit entry recording the operation itself (``USER_FORGOTTEN`` /
``AUDIT_PRUNED``), so the *act* of forgetting or pruning is itself in the
immutable history (with no PII inside).
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import timedelta
from typing import Any

from django.db import connection, transaction
from django.utils import timezone

from .models import AccessLogEntry, Action, AuditLogEntry
from .services import record

log = logging.getLogger(__name__)

# Replacement text written over forgotten users' comment bodies (and their
# append-only edit-history rows). Kept as a single constant so the live comment
# and its versions read identically.
_COMMENT_REDACTION_PLACEHOLDER = "[redacted by user-forget request]"


@contextmanager
def _audit_trigger_bypass():
    """Temporarily allow UPDATE/DELETE on audit_auditlogentry."""
    with connection.cursor() as cur:
        cur.execute("SET LOCAL session_replication_role = replica")
        try:
            yield
        finally:
            cur.execute("SET LOCAL session_replication_role = origin")


# ---------------------------------------------------------------------------
# forget_user
# ---------------------------------------------------------------------------


def forget_user(
    user,
    *,
    by=None,
    reason: str = "",
    ip_address: str | None = None,
    user_agent: str | None = None,
    anonymized_email: str | None = None,
) -> dict[str, int]:
    """Anonymize ``user`` across the system, return per-source counters.

    The user row itself is mutated (email/display_name/oidc_subject
    blanked), not deleted, so existing FK-NULL columns keep their
    structural meaning. If you also want the row gone afterwards, call
    ``user.delete()`` separately.

    ``by`` is the requesting operator (an admin via the console, or ``None``
    on the CLI path); it, the ``reason``, and the source ``ip_address`` /
    ``user_agent`` are recorded on the durable ``USER_FORGOTTEN`` audit entry
    (the reason is secret-redacted). The entry carries no PII of the forgotten
    subject — only its pk and the scrub counters.
    """
    pseudo = anonymized_email or f"forgotten-{user.pk}@example.invalid"
    counters = {
        "audit_entries": 0,
        "access_log_entries": 0,
        "comments": 0,
        "comment_versions": 0,
        "invitations": 0,
        "intake_reports": 0,
    }

    with transaction.atomic(), _audit_trigger_bypass():
        # 1. Audit JSON fields — scrub any literal occurrence of the user's
        # original email/display_name. Iterate only entries that referenced
        # this user (FK or text match) to keep the work bounded.
        original_email = user.email
        original_display = user.display_name or ""
        targets = AuditLogEntry.objects.filter(actor=user) | AuditLogEntry.objects.filter(
            metadata__icontains=original_email
        )
        for entry in targets.iterator():
            mutated = False
            for field_name in ("previous_value", "new_value", "metadata"):
                original = getattr(entry, field_name)
                replaced = _scrub_json(original, original_email, pseudo, original_display)
                if replaced != original:
                    setattr(entry, field_name, replaced)
                    mutated = True
            if mutated:
                # ``save()`` is normally blocked for existing rows; bypass it.
                AuditLogEntry.objects.filter(pk=entry.pk).update(
                    previous_value=entry.previous_value,
                    new_value=entry.new_value,
                    metadata=entry.metadata,
                )
                counters["audit_entries"] += 1

        # 1b. Access-log rows (views + GHSA/PMI chatter) carry the user's
        # actor FK, IP, and user-agent. The access log is a retention-bounded,
        # non-compliance store, so delete the user's rows outright rather than
        # scrub them. No append-only trigger on this table, so the bypass isn't
        # needed here — but running inside it is harmless.
        deleted_access, _ = AccessLogEntry.objects.filter(actor=user).delete()
        counters["access_log_entries"] = deleted_access

        # 2. Their authored comments — redact body, keep the structural
        # presence so reply threads stay coherent. The append-only
        # ``CommentVersion`` edit-history rows hold the same authored text, so
        # scrub those too. A bulk ``update()`` bypasses ``CommentVersion``'s
        # write-once ``save()`` guard; there's no Postgres trigger on that
        # table (only ``AuditLogEntry`` has one), so it needs no special
        # handling. Scoped to comments the user *authored* — we don't touch
        # versions they merely edited on someone else's comment.
        try:
            from comments.models import AdvisoryComment, CommentVersion

            comments = AdvisoryComment.objects.filter(author=user)
            for c in comments:
                if c.body:
                    c.body = _COMMENT_REDACTION_PLACEHOLDER
                c.redacted_at = c.redacted_at or timezone.now()
                c.save(update_fields=["body", "redacted_at"])
                counters["comments"] += 1
            counters["comment_versions"] = CommentVersion.objects.filter(
                comment__author=user
            ).update(body=_COMMENT_REDACTION_PLACEHOLDER)
        except Exception:
            log.exception("comments scrub failed during forget_user(%s)", user.pk)

        # 3. Pending invitations they created — drop them entirely.
        try:
            from access.models import PendingInvitation

            deleted, _ = PendingInvitation.objects.filter(created_by=user).delete()
            counters["invitations"] = deleted
        except Exception:
            log.exception("invitations scrub failed during forget_user(%s)", user.pk)

        # 4. Triage-advisory intake sidecars they submitted — scrub PII in
        # place. The Advisory itself persists (audit trail coherence); the
        # sidecar's identity + network fields are blanked. ``reporter_user``
        # is nulled so future joins don't surface the (now-anonymized) user.
        # Reporter REPORTER-credit entries on the advisory carrying this
        # user's email are stripped as well.
        try:
            from advisories.models import Advisory, AdvisoryIntakeMetadata

            scrubbed_intakes = AdvisoryIntakeMetadata.objects.filter(reporter_user=user).update(
                reporter_user=None,
                reporter_display_name="",
                submitted_ip=None,
                submitted_user_agent="",
                pii_cleared_at=timezone.now(),
            )
            counters["intake_metadata"] = scrubbed_intakes

            # Walk credits looking for mailto:<user.email>; strip matching
            # entries. Curated credits the triager added by hand against the
            # original (now reset) email are caught here too.
            email_marker = f"mailto:{(user.email or '').strip().lower()}"
            stripped_credits = 0
            if email_marker != "mailto:":
                for adv in Advisory.objects.exclude(credits=[]).iterator():
                    credits = adv.credits or []
                    filtered = [
                        c
                        for c in credits
                        if email_marker
                        not in [str(x).strip().lower() for x in (c.get("contact") or [])]
                    ]
                    if len(filtered) != len(credits):
                        adv.credits = filtered
                        adv.save(update_fields=["credits", "modified_at"])
                        stripped_credits += 1
            counters["credits_stripped"] = stripped_credits
        except Exception:
            log.exception("advisory intake scrub failed during forget_user(%s)", user.pk)

        # 4b. Honeypot rows are not user-linked, but if the submitter happens
        # to share an IP with the user's recorded submissions we don't scrub
        # them here — they're scrubbed by the time-based ``prune_honeypots``
        # job, which is what retention SLAs target anyway.

        # 4c. Security-team roster rows mirror the member's Eclipse email and
        # name from PMI. Unlike comments/audit (kept for coherence), the roster
        # is a disposable mirror, so delete the user's rows outright — that
        # removes the email/name without risking the ``(project,
        # eclipse_username)`` unique constraint a blank-out would hit. If the
        # member is still on the PMI team a future sync re-mirrors them (their
        # email is legitimately processed while they serve); forget_user purges
        # current data, it doesn't block lawful re-collection. See INV-OIDC-5.
        try:
            from projects.models import SecurityTeamRosterEntry

            deleted_roster, _ = SecurityTeamRosterEntry.objects.filter(user=user).delete()
            counters["roster_entries"] = deleted_roster
        except Exception:
            log.exception("security roster scrub failed during forget_user(%s)", user.pk)

        # 5. Mutate the User row last so the queries above can still find it.
        user.email = pseudo
        user.display_name = ""
        user.first_name = ""
        user.last_name = ""
        user.oidc_subject = ""
        user.is_active = False
        user.save()

        # 6. Audit the act of forgetting itself on the durable ledger. Routed
        # through ``record`` so the action is validated and the operator-typed
        # reason is secret-redacted (INV-AUDIT-2). The fresh INSERT is allowed
        # inside the trigger-bypass block — the append-only trigger only blocks
        # UPDATE/DELETE.
        record(
            action=Action.USER_FORGOTTEN,
            actor=by,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={
                "operation": "forget_user",
                "subject_pk": user.pk,
                "counters": counters,
                "reason": reason,
                "via": "admin_console" if by else "cli",
            },
        )

    return counters


def _scrub_json(value: Any, email: str, pseudo: str, display: str) -> Any:
    """Recursively replace ``email`` and ``display`` literals inside a JSON tree."""
    if value is None:
        return None
    if isinstance(value, str):
        out = value.replace(email, pseudo)
        if display:
            out = out.replace(display, "[redacted]")
        return out
    if isinstance(value, dict):
        return {k: _scrub_json(v, email, pseudo, display) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_json(v, email, pseudo, display) for v in value]
    return value


# ---------------------------------------------------------------------------
# prune_audit_older_than
# ---------------------------------------------------------------------------


def prune_audit_older_than(
    days: int,
    *,
    dry_run: bool = False,
    by=None,
    reason: str = "",
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> int:
    """Delete audit entries older than ``days`` and return the row count.

    With ``dry_run=True`` no rows are deleted and the count is just the
    number that *would* be removed. Use the management command
    (``manage.py prune_audit --older-than-days …``) for the standard
    operator workflow rather than calling this directly.

    Every non-dry-run call records an ``AUDIT_PRUNED`` entry on the ledger
    (horizon, exact cutoff, deleted row count) — even when zero rows
    matched, since the act of running the sweep is what's audited.
    ``by`` / ``reason`` / ``ip_address`` / ``user_agent`` describe the
    requesting operator, as in :func:`forget_user`; the ``reason`` is
    secret-redacted before it lands in metadata (INV-AUDIT-2).
    """
    if days <= 0:
        raise ValueError("days must be positive")
    cutoff = timezone.now() - timedelta(days=days)
    qs = AuditLogEntry.objects.filter(created_at__lt=cutoff)
    if dry_run:
        return qs.count()

    with transaction.atomic(), _audit_trigger_bypass():
        deleted, _ = qs.delete()
        # Audit the act of pruning itself on the durable ledger (same pattern
        # as forget_user above). The fresh INSERT is allowed inside the
        # trigger-bypass block — the append-only trigger only blocks
        # UPDATE/DELETE — and sharing the transaction means a prune can never
        # commit unrecorded: if this insert fails, the delete rolls back. The
        # entry is dated *now*, after the delete ran, so it can never fall
        # inside its own cutoff.
        record(
            action=Action.AUDIT_PRUNED,
            actor=by,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={
                "operation": "prune_audit",
                "older_than_days": days,
                "cutoff": cutoff.isoformat(),
                "deleted": deleted,
                "reason": reason,
                "via": "admin_console" if by else "cli",
            },
        )
    return deleted
