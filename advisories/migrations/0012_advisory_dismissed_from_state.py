"""Add ``Advisory.dismissed_from_state`` for the reopen flow.

The reopen feature needs to know which state the advisory was in immediately
before dismissal (``triage`` or ``draft``) so it can route the row back to
its rightful place. Backfill existing dismissed advisories by inspecting the
audit log's latest ``advisory.state_changed`` entry that landed them in
``dismissed``; fall back to ``draft`` if no such row exists (oldest seed
data, pre-audit instrumentation).
"""

from django.db import migrations, models


def _backfill_dismissed_from_state(apps, schema_editor):
    Advisory = apps.get_model("advisories", "Advisory")
    AuditLogEntry = apps.get_model("audit", "AuditLogEntry")

    dismissed = Advisory.objects.filter(state="dismissed", dismissed_from_state="")
    for advisory in dismissed.iterator():
        prior = (
            AuditLogEntry.objects.filter(
                advisory=advisory,
                action="advisory.state_changed",
                new_value__state="dismissed",
            )
            .order_by("-created_at")
            .values_list("previous_value", flat=True)
            .first()
        )
        prior_state = (prior or {}).get("state") if isinstance(prior, dict) else None
        advisory.dismissed_from_state = (
            prior_state if prior_state in ("triage", "draft") else "draft"
        )
        advisory.save(update_fields=["dismissed_from_state"])


class Migration(migrations.Migration):
    dependencies = [
        ("advisories", "0011_delete_advisory_snapshot"),
        ("audit", "0017_reopen_advisory"),
    ]

    operations = [
        migrations.AddField(
            model_name="advisory",
            name="dismissed_from_state",
            field=models.CharField(
                blank=True,
                choices=[
                    ("triage", "Triage"),
                    ("draft", "Draft"),
                    ("published", "Published"),
                    ("dismissed", "Dismissed"),
                ],
                default="",
                max_length=16,
            ),
        ),
        migrations.RunPython(_backfill_dismissed_from_state, migrations.RunPython.noop),
    ]
