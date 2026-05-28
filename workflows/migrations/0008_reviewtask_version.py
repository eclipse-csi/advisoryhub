"""Re-key ``ReviewTask`` from ``AdvisorySnapshot`` to ``AdvisoryVersion``.

Symmetric to ``publication.0003`` — the review task pins the exact
content the reviewer is judging. After this migration, that pointer
references the new append-only ``AdvisoryVersion`` log instead of the
soon-to-be-removed ``AdvisorySnapshot`` table.
"""

from __future__ import annotations

from django.db import migrations, models
import django.db.models.deletion


def _backfill_version(apps, schema_editor):
    ReviewTask = apps.get_model("workflows", "ReviewTask")
    AdvisoryVersion = apps.get_model("advisories", "AdvisoryVersion")
    for task in ReviewTask.objects.select_related("advisory").iterator():
        version = (
            AdvisoryVersion.objects.filter(advisory_id=task.advisory_id).order_by("version").first()
        )
        if version is None:
            continue
        task.version = version
        task.save(update_fields=["version"])


def _restore_snapshot(apps, schema_editor):  # pragma: no cover — irreversible
    return


class Migration(migrations.Migration):
    dependencies = [
        ("workflows", "0007_alter_reviewtask_status"),
        ("advisories", "0010_advisory_version"),
    ]

    operations = [
        migrations.AddField(
            model_name="reviewtask",
            name="version",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="review_tasks",
                to="advisories.advisoryversion",
            ),
        ),
        migrations.RunPython(_backfill_version, _restore_snapshot),
        migrations.AlterField(
            model_name="reviewtask",
            name="version",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="review_tasks",
                to="advisories.advisoryversion",
            ),
        ),
        migrations.RemoveField(
            model_name="reviewtask",
            name="snapshot",
        ),
    ]
