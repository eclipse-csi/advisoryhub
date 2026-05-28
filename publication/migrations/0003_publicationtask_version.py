"""Re-key ``PublicationTask`` from ``AdvisorySnapshot`` to ``AdvisoryVersion``.

The snapshot/version relationship is one-to-one in terms of intent — the
publication task pins the exact frozen content it pushed. After this
migration, the FK points into the new append-only ``AdvisoryVersion`` log,
which captures every edit (not just publication and review milestones).

We add the new FK as nullable, backfill it from the advisory's first
``AdvisoryVersion`` (created by ``advisories.0010``), tighten the
nullability, and drop the legacy ``snapshot`` FK in the same migration.
"""

from __future__ import annotations

from django.db import migrations, models
import django.db.models.deletion


def _backfill_version(apps, schema_editor):
    PublicationTask = apps.get_model("publication", "PublicationTask")
    AdvisoryVersion = apps.get_model("advisories", "AdvisoryVersion")
    # Every Advisory got a v1 from advisories.0010; pin existing tasks to it.
    # If a task somehow has no matching version (impossible after 0010), leave
    # the FK null and let the AlterField step raise — a loud failure here is
    # better than silently orphaning a publication record.
    for task in PublicationTask.objects.select_related("advisory").iterator():
        version = (
            AdvisoryVersion.objects.filter(advisory_id=task.advisory_id).order_by("version").first()
        )
        if version is None:
            continue
        task.version = version
        task.save(update_fields=["version"])


def _restore_snapshot(apps, schema_editor):  # pragma: no cover — irreversible
    # Going back is meaningless once AdvisorySnapshot rows are dropped in
    # advisories.0011. The reverse migration is provided only to keep
    # Django's reverse() happy in dev rollbacks; it deliberately does
    # nothing and will leave the schema half-reverted.
    return


class Migration(migrations.Migration):
    dependencies = [
        ("publication", "0002_rename_pub_status_idx_publication_status_ddceed_idx_and_more"),
        ("advisories", "0010_advisory_version"),
    ]

    operations = [
        migrations.AddField(
            model_name="publicationtask",
            name="version",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="publication_tasks",
                to="advisories.advisoryversion",
            ),
        ),
        migrations.RunPython(_backfill_version, _restore_snapshot),
        migrations.AlterField(
            model_name="publicationtask",
            name="version",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="publication_tasks",
                to="advisories.advisoryversion",
            ),
        ),
        migrations.RemoveField(
            model_name="publicationtask",
            name="snapshot",
        ),
    ]
