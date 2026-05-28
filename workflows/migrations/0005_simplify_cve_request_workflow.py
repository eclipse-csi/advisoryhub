from django.db import migrations, models


def _in_progress_to_queued(apps, schema_editor):
    CveRequestTask = apps.get_model("workflows", "CveRequestTask")
    CveRequestTask.objects.filter(status="in_progress").update(status="queued")


class Migration(migrations.Migration):
    dependencies = [
        ("workflows", "0004_orphan_cve"),
    ]

    operations = [
        migrations.RunPython(_in_progress_to_queued, migrations.RunPython.noop),
        migrations.RemoveConstraint(
            model_name="cverequesttask",
            name="cve_request_one_open_per_advisory",
        ),
        migrations.AlterField(
            model_name="cverequesttask",
            name="status",
            field=models.CharField(
                choices=[
                    ("queued", "Queued"),
                    ("reserved", "Reserved"),
                    ("rejected", "Rejected"),
                    ("cancelled", "Cancelled"),
                ],
                default="queued",
                max_length=16,
            ),
        ),
        migrations.RemoveField(
            model_name="cverequesttask",
            name="started_at",
        ),
        migrations.AddConstraint(
            model_name="cverequesttask",
            constraint=models.UniqueConstraint(
                condition=models.Q(("status", "queued")),
                fields=("advisory",),
                name="cve_request_one_open_per_advisory",
            ),
        ),
    ]
