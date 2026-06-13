from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from advisories.models import Advisory
from audit.models import Action, AuditLogEntry
from audit.retention import _audit_trigger_bypass, forget_user, prune_audit_older_than
from audit.services import record


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    member = make_user(email="alice@example.org")
    member.display_name = "Alice Doe"
    member.save(update_fields=["display_name"])
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x", created_by=member)
    return {"member": member, "advisory": advisory, "project": project}


# ---- forget_user --------------------------------------------------------


@pytest.mark.django_db
def test_forget_user_anonymizes_user_row(setup):
    counters = forget_user(setup["member"])
    setup["member"].refresh_from_db()
    assert setup["member"].email != "alice@example.org"
    assert setup["member"].display_name == ""
    assert setup["member"].is_active is False
    assert counters["audit_entries"] >= 0  # may be 0 if no audit referenced the email


@pytest.mark.django_db
def test_forget_user_scrubs_audit_metadata(setup):
    """Audit metadata containing the original email gets scrubbed."""
    record(
        action=Action.ADVISORY_EDITED,
        actor=setup["member"],
        advisory=setup["advisory"],
        metadata={"reporter_email": "alice@example.org", "note": "Alice Doe reviewed"},
    )
    forget_user(setup["member"])
    entry = AuditLogEntry.objects.filter(action=Action.ADVISORY_EDITED).first()
    assert entry is not None
    assert "alice@example.org" not in str(entry.metadata)
    assert "Alice Doe" not in str(entry.metadata)


@pytest.mark.django_db
def test_forget_user_redacts_authored_comments(setup):
    from comments.services import add_comment

    c = add_comment(setup["advisory"], author=setup["member"], body="My personal note")
    forget_user(setup["member"])
    c.refresh_from_db()
    assert c.body == "[redacted by user-forget request]"
    assert c.is_redacted


@pytest.mark.django_db
def test_forget_user_scrubs_comment_version_history(setup):
    """Every append-only ``CommentVersion`` of an authored comment — not just
    the live body — is overwritten with the placeholder."""
    from comments.models import CommentVersion
    from comments.services import add_comment, edit_comment

    c = add_comment(setup["advisory"], author=setup["member"], body="original secret")
    edit_comment(c, by=setup["member"], new_body="edited secret")
    versions = CommentVersion.objects.filter(comment=c)
    assert versions.count() == 2  # v1 + v2

    counters = forget_user(setup["member"])

    assert counters["comment_versions"] == 2
    assert versions.count() == 2  # rows are NOT deleted, only their bodies scrubbed
    for v in versions:
        assert v.body == "[redacted by user-forget request]"


@pytest.mark.django_db
def test_forget_user_drops_their_pending_invitations(setup):
    from access.models import PendingInvitation, Permission
    from access.services import invite_email

    invite_email(setup["advisory"], "newcomer@example.org", Permission.VIEWER, by=setup["member"])
    assert PendingInvitation.objects.filter(created_by=setup["member"]).exists()
    forget_user(setup["member"])
    assert not PendingInvitation.objects.filter(created_by=setup["member"]).exists()


@pytest.mark.django_db
def test_forget_user_deletes_access_log_rows(setup):
    """Access-log rows (views/chatter) carry actor + IP/UA; forget deletes them."""
    from audit.models import AccessLogEntry

    record(
        action=Action.ADVISORY_VIEWED,
        actor=setup["member"],
        advisory=setup["advisory"],
        ip_address="198.51.100.7",
        user_agent="curl/8.5.0",
    )
    assert AccessLogEntry.objects.filter(actor=setup["member"]).exists()
    counters = forget_user(setup["member"])
    assert AccessLogEntry.objects.filter(actor=setup["member"]).count() == 0
    assert counters["access_log_entries"] >= 1


@pytest.mark.django_db
def test_forget_user_records_audit_of_the_forgetting(setup):
    forget_user(setup["member"])
    forget_audit = AuditLogEntry.objects.filter(metadata__operation="forget_user").first()
    assert forget_audit is not None
    assert forget_audit.action == Action.USER_FORGOTTEN
    assert forget_audit.metadata["subject_pk"] == setup["member"].pk
    # No requesting operator on the CLI path.
    assert forget_audit.actor_id is None
    assert forget_audit.metadata["via"] == "cli"


@pytest.mark.django_db
def test_forget_user_records_requesting_operator_and_reason(make_user, setup):
    """The admin-console path records who requested the erasure, the source
    IP/UA, and a secret-redacted justification on the USER_FORGOTTEN entry."""
    operator = make_user(email="operator@example.org")
    forget_user(
        setup["member"],
        by=operator,
        reason="GDPR ticket #42; token ghp_abcdefghijklmnopqrstuvwx leaked",
        ip_address="198.51.100.9",
        user_agent="Mozilla/5.0",
    )
    entry = AuditLogEntry.objects.get(action=Action.USER_FORGOTTEN)
    assert entry.actor_id == operator.pk
    assert entry.ip_address == "198.51.100.9"
    assert entry.metadata["via"] == "admin_console"
    assert entry.metadata["subject_pk"] == setup["member"].pk
    # Reason is recorded but funnelled through redact_secrets (INV-AUDIT-2).
    assert "ghp_" not in entry.metadata["reason"]
    assert "***" in entry.metadata["reason"]
    assert "GDPR ticket #42" in entry.metadata["reason"]


@pytest.mark.django_db
def test_forget_user_scrubs_advisory_intake_sidecar(setup):
    """``AdvisoryIntakeMetadata`` rows referencing the user have their
    reporter identity, IP, and UA blanked; ``pii_cleared_at`` is set.
    """
    from advisories.models import AdvisoryIntakeMetadata, State

    triage = Advisory.objects.create(
        project=setup["project"],
        state=State.TRIAGE,
        summary="t",
        created_by=setup["member"],
    )
    AdvisoryIntakeMetadata.objects.create(
        advisory=triage,
        reporter_user=setup["member"],
        reporter_display_name="Alice Doe",
        submitted_ip="198.51.100.1",
        submitted_user_agent="curl/8.5.0",
    )
    counters = forget_user(setup["member"])
    assert counters.get("intake_metadata") == 1
    intake = AdvisoryIntakeMetadata.objects.get(advisory=triage)
    assert intake.reporter_user is None
    assert intake.reporter_display_name == ""
    assert intake.submitted_ip is None
    assert intake.submitted_user_agent == ""
    assert intake.pii_cleared_at is not None
    # The advisory itself persists — only PII on the sidecar is scrubbed.
    triage.refresh_from_db()
    assert triage.state == State.TRIAGE


@pytest.mark.django_db
def test_forget_user_strips_reporter_credit_with_matching_email(setup):
    """Credits added by triagers carrying ``mailto:<user.email>`` are
    stripped from the advisory.
    """
    from advisories.models import State

    triage = Advisory.objects.create(
        project=setup["project"],
        state=State.TRIAGE,
        summary="t",
        credits=[
            {"name": "Alice Doe", "type": "REPORTER", "contact": ["mailto:alice@example.org"]},
            {"name": "Bob Builder", "type": "REPORTER", "contact": ["mailto:bob@example.org"]},
        ],
    )
    forget_user(setup["member"])
    triage.refresh_from_db()
    assert len(triage.credits) == 1
    assert triage.credits[0]["name"] == "Bob Builder"


# ---- prune_audit_older_than --------------------------------------------


@pytest.mark.django_db
def test_prune_audit_dry_run_does_not_delete(setup):
    record(action=Action.ADVISORY_CREATED, actor=setup["member"], advisory=setup["advisory"])
    # Backdate the entry by hand (bypass the append-only triggers via the
    # same context manager production code uses).
    with _audit_trigger_bypass():
        AuditLogEntry.objects.all().update(created_at=timezone.now() - timedelta(days=400))

    n = prune_audit_older_than(365, dry_run=True)
    assert n >= 1
    assert AuditLogEntry.objects.count() >= 1  # nothing actually deleted


@pytest.mark.django_db
def test_prune_audit_deletes_old_entries(setup):
    record(action=Action.ADVISORY_CREATED, actor=setup["member"], advisory=setup["advisory"])
    record(action=Action.ADVISORY_EDITED, actor=setup["member"], advisory=setup["advisory"])

    # Backdate one entry to be old, leave the other young.
    with _audit_trigger_bypass():
        old = AuditLogEntry.objects.filter(action=Action.ADVISORY_CREATED).first()
        AuditLogEntry.objects.filter(pk=old.pk).update(
            created_at=timezone.now() - timedelta(days=400)
        )

    n = prune_audit_older_than(365)
    assert n >= 1
    assert not AuditLogEntry.objects.filter(pk=old.pk).exists()
    # The recent one survived.
    assert AuditLogEntry.objects.filter(action=Action.ADVISORY_EDITED).exists()


@pytest.mark.django_db
def test_prune_audit_rejects_zero_or_negative(setup):
    with pytest.raises(ValueError):
        prune_audit_older_than(0)
    with pytest.raises(ValueError):
        prune_audit_older_than(-1)


@pytest.mark.django_db
def test_prune_audit_records_audit_of_the_pruning(setup):
    record(action=Action.ADVISORY_CREATED, actor=setup["member"], advisory=setup["advisory"])
    with _audit_trigger_bypass():
        AuditLogEntry.objects.all().update(created_at=timezone.now() - timedelta(days=400))

    deleted = prune_audit_older_than(365)

    entry = AuditLogEntry.objects.get(action=Action.AUDIT_PRUNED)
    assert entry.metadata["operation"] == "prune_audit"
    assert entry.metadata["older_than_days"] == 365
    assert entry.metadata["deleted"] == deleted == 1
    # No requesting operator on the CLI path.
    assert entry.actor_id is None
    assert entry.metadata["via"] == "cli"
    # The entry post-dates the cutoff it records, so it survives its own sweep.
    assert datetime.fromisoformat(entry.metadata["cutoff"]) < entry.created_at


@pytest.mark.django_db
def test_prune_audit_records_even_when_nothing_matched(setup):
    assert prune_audit_older_than(365) == 0
    entry = AuditLogEntry.objects.get(action=Action.AUDIT_PRUNED)
    assert entry.metadata["deleted"] == 0


@pytest.mark.django_db
def test_prune_audit_dry_run_records_nothing(setup):
    prune_audit_older_than(365, dry_run=True)
    assert not AuditLogEntry.objects.filter(action=Action.AUDIT_PRUNED).exists()


@pytest.mark.django_db
def test_prune_audit_records_requesting_operator_and_reason(make_user, setup):
    """The operator path records who requested the sweep, the source IP/UA,
    and a secret-redacted justification on the AUDIT_PRUNED entry."""
    operator = make_user(email="operator@example.org")
    prune_audit_older_than(
        365,
        by=operator,
        reason="retention ticket #7; token ghp_abcdefghijklmnopqrstuvwx leaked",
        ip_address="198.51.100.9",
        user_agent="Mozilla/5.0",
    )
    entry = AuditLogEntry.objects.get(action=Action.AUDIT_PRUNED)
    assert entry.actor_id == operator.pk
    assert entry.ip_address == "198.51.100.9"
    assert entry.metadata["via"] == "admin_console"
    # Reason is recorded but funnelled through redact_secrets (INV-AUDIT-2).
    assert "ghp_" not in entry.metadata["reason"]
    assert "***" in entry.metadata["reason"]
    assert "retention ticket #7" in entry.metadata["reason"]


# ---- management command -------------------------------------------------


@pytest.mark.django_db
def test_forget_user_command(setup, capsys):
    call_command("forget_user", "alice@example.org")
    setup["member"].refresh_from_db()
    assert setup["member"].email != "alice@example.org"


@pytest.mark.django_db
def test_forget_user_command_unknown_email(setup):
    from django.core.management import CommandError

    with pytest.raises(CommandError):
        call_command("forget_user", "nope@example.org")


@pytest.mark.django_db
def test_prune_audit_command(setup, capsys):
    record(action=Action.ADVISORY_CREATED, actor=setup["member"], advisory=setup["advisory"])
    with _audit_trigger_bypass():
        AuditLogEntry.objects.all().update(created_at=timezone.now() - timedelta(days=400))

    call_command("prune_audit", "--older-than-days=365", "--dry-run")
    # Nothing was deleted — dry-run.
    assert AuditLogEntry.objects.count() >= 1

    call_command("prune_audit", "--older-than-days=365")
    # The backdated entry is gone; the only remaining row is the prune's own record.
    remaining = AuditLogEntry.objects.all()
    assert remaining.count() == 1
    assert remaining.get().action == Action.AUDIT_PRUNED


@pytest.mark.django_db
def test_forget_user_deletes_roster_rows(setup):
    """A forgotten user's security-team roster rows are deleted so their
    Eclipse email/name don't survive (INV-OIDC-5)."""
    from django.utils import timezone

    from projects.models import SecurityTeamRosterEntry

    SecurityTeamRosterEntry.objects.create(
        project=setup["project"],
        eclipse_username="alice",
        email=setup["member"].email,
        user=setup["member"],
        last_seen_in_pmi_at=timezone.now(),
    )
    counters = forget_user(setup["member"])
    assert counters["roster_entries"] == 1
    assert not SecurityTeamRosterEntry.objects.filter(user=setup["member"]).exists()
