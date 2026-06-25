from django.db import migrations, models


def backfill_severity(apps, schema_editor):
    """Populate the denormalised severity columns for existing advisories.

    ``effective_severity`` is a pure helper (CVSS parsing only, no model
    dependency), so importing it here is safe and keeps the bucketing identical
    to the runtime ``Advisory.save`` path. ``.update()`` is used so the backfill
    doesn't bump ``modified_at`` (auto_now) — Advisory has no append-only DB
    trigger, so a bulk update is allowed on Postgres.
    """
    from advisories.severity import effective_severity

    Advisory = apps.get_model("advisories", "Advisory")
    for adv in Advisory.objects.all().only("pk", "severity").iterator():
        level, score = effective_severity(adv.severity)
        Advisory.objects.filter(pk=adv.pk).update(severity_level=level, severity_score=score)


class Migration(migrations.Migration):
    dependencies = [
        ("advisories", "0008_advisory_comments_lock_reason_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="advisory",
            name="severity_level",
            field=models.CharField(
                choices=[
                    ("critical", "Critical"),
                    ("high", "High"),
                    ("medium", "Medium"),
                    ("low", "Low"),
                    ("none", "Unscored"),
                ],
                db_index=True,
                default="none",
                max_length=12,
            ),
        ),
        migrations.AddField(
            model_name="advisory",
            name="severity_score",
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.RunPython(backfill_severity, migrations.RunPython.noop),
    ]
