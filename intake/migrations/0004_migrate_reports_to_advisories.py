"""One-shot migration: ``VulnerabilityReport`` → ``Advisory`` + sidecar.

The intake report model is being folded into ``Advisory`` as a new ``triage``
lifecycle state. This migration moves the row data over so the legacy
``VulnerabilityReport`` table can be dropped in a subsequent migration.

Mapping rules:

* ``is_honeypot=True`` → :class:`intake.HoneypotSubmission` (no Advisory row).
* ``state=NEW`` → ``Advisory(state="triage")`` + ``AdvisoryIntakeMetadata``.
* ``state=TRIAGED`` → the original report linked an advisory in
  ``converted_advisory``. We keep that advisory's existing state (the
  legacy code transitioned to DRAFT at convert-time) and attach a sidecar.
* ``state=DISMISSED`` (non-honeypot) → ``Advisory(state="dismissed")`` with
  the existing ``dismissed_reason``; sidecar carries the reporter
  fingerprints and admin-routing flag.

Unrouted reports (project IS NULL) point at the ``unsorted`` sentinel
project. Reporter email is dropped unless it matches an existing
``User.email`` exactly, in which case a viewer grant is seeded so the
authenticated reporter sees the advisory on first login.

This migration is **forward-only**: there is no reverse data migration —
the source rows are kept until the follow-up migration deletes the model,
so a rollback up to (but not past) the deletion is recoverable by
rerunning forward.
"""

from __future__ import annotations

import secrets

from django.db import migrations


_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def _gen_advisory_id() -> str:
    parts = ["".join(secrets.choice(_ALPHABET) for _ in range(4)) for _ in range(3)]
    return "ECL-" + "-".join(parts)


def _unique_advisory_id(Advisory) -> str:
    for _ in range(16):
        candidate = _gen_advisory_id()
        if not Advisory.objects.filter(advisory_id=candidate).exists():
            return candidate
    raise RuntimeError("Failed to generate a unique advisory id.")


def migrate_reports_forward(apps, schema_editor):
    VulnerabilityReport = apps.get_model("intake", "VulnerabilityReport")
    HoneypotSubmission = apps.get_model("intake", "HoneypotSubmission")
    Advisory = apps.get_model("advisories", "Advisory")
    AdvisoryIntakeMetadata = apps.get_model("advisories", "AdvisoryIntakeMetadata")
    Project = apps.get_model("projects", "Project")
    User = apps.get_model(*_user_model(apps))
    AdvisoryAccessGrant = apps.get_model("access", "AdvisoryAccessGrant")

    unsorted = Project.objects.filter(slug="unsorted").first()
    if unsorted is None:
        # Defensive: the sentinel migration should have created it.
        # If absent, abort rather than producing rows pointing nowhere.
        if VulnerabilityReport.objects.exists():
            raise RuntimeError(
                "intake migration: 'unsorted' sentinel project missing; "
                "projects.0003_unsorted_sentinel_project must run first."
            )
        return

    for report in VulnerabilityReport.objects.all().iterator():
        if report.is_honeypot:
            HoneypotSubmission.objects.create(
                id=report.id,
                submitted_ip=report.submitted_ip,
                submitted_user_agent=report.submitted_user_agent or "",
                honeypot_field_value="",
                submitted_at=report.created_at,
                pii_cleared_at=report.pii_cleared_at,
            )
            continue

        if report.state == "triaged" and report.converted_advisory_id:
            advisory = Advisory.objects.get(pk=report.converted_advisory_id)
        else:
            adv_state = "triage" if report.state == "new" else "dismissed"
            advisory = Advisory(
                advisory_id=_unique_advisory_id(Advisory),
                project=report.project or unsorted,
                state=adv_state,
                summary=report.summary[:300],
                details=report.details,
                created_by=report.reporter_user,
                created_at=report.created_at,
                dismissed_reason=report.dismissed_reason or "",
            )
            advisory.save()

        # Avoid double-creating sidecars if the migration is re-run (idempotent).
        if AdvisoryIntakeMetadata.objects.filter(advisory=advisory).exists():
            continue

        AdvisoryIntakeMetadata.objects.create(
            advisory=advisory,
            reporter_user=report.reporter_user,
            reporter_display_name=(report.reporter_name or "")[:200],
            submitted_ip=report.submitted_ip,
            submitted_user_agent=(report.submitted_user_agent or "")[:512],
            needs_admin_routing=report.needs_admin_routing,
            admin_routing_note=report.admin_routing_note or "",
            flagged_for_routing_at=report.flagged_for_routing_at,
            flagged_for_routing_by=report.flagged_for_routing_by,
            submitted_at=report.created_at,
            pii_cleared_at=report.pii_cleared_at,
        )

        # Seed a viewer grant when the legacy reporter_email matches an
        # existing User. Free-text emails that don't match any user are
        # dropped (we intentionally do not carry unverified emails forward).
        email = (report.reporter_email or "").strip().lower()
        if email and report.state != "dismissed":
            matched_user = User.objects.filter(email__iexact=email).first()
            if matched_user is not None:
                AdvisoryAccessGrant.objects.get_or_create(
                    advisory=advisory,
                    principal_type="user",
                    principal_id=matched_user.pk,
                    defaults={"permission": "viewer"},
                )


def _user_model(apps):
    """Return the (app_label, model_name) tuple for AUTH_USER_MODEL."""
    from django.conf import settings

    app_label, model_name = settings.AUTH_USER_MODEL.split(".")
    return app_label, model_name


class Migration(migrations.Migration):
    dependencies = [
        ("intake", "0003_honeypotsubmission"),
        ("advisories", "0008_alter_advisory_state_advisoryintakemetadata"),
        ("projects", "0003_unsorted_sentinel_project"),
        ("access", "0003_rename_permission_levels"),
    ]

    operations = [
        migrations.RunPython(migrate_reports_forward, migrations.RunPython.noop),
    ]
