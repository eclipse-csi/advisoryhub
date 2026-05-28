"""Workflows model changes for the reopen-advisory flow.

Adds the ``OrphanCveReassignmentTask`` model — the admin to-do raised when
an advisory is reopened but its prior CVE has already been marked rejected
at cve.org — and extends ``OrphanCveStatus`` with the terminal ``reassigned``
value reached either directly (orphan was still ``orphaned`` when reopen
ran) or via a resolved reassignment task.
"""

import advisories.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("advisories", "0012_advisory_dismissed_from_state"),
        ("workflows", "0008_reviewtask_version"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name="orphancve",
            name="status",
            field=models.CharField(
                choices=[
                    ("orphaned", "Orphaned (awaiting cve.org rejection)"),
                    ("marked_rejected", "Marked as rejected at cve.org"),
                    ("reassigned", "Reassigned back to advisory"),
                ],
                default="orphaned",
                max_length=24,
            ),
        ),
        migrations.CreateModel(
            name="OrphanCveReassignmentTask",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("resolved_reassigned", "Resolved — CVE reattached"),
                            ("resolved_replaced", "Resolved — replaced with a new CVE"),
                        ],
                        default="queued",
                        max_length=24,
                    ),
                ),
                ("replacement_cve_id", models.CharField(blank=True, max_length=32)),
                ("resolution_notes", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                (
                    "advisory",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="orphan_reassignment_tasks",
                        to="advisories.advisory",
                    ),
                ),
                (
                    "orphan_cve",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="reassignment_tasks",
                        to="workflows.orphancve",
                    ),
                ),
                (
                    "requested_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "resolved_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(
                        fields=["status", "created_at"],
                        name="workflows_o_status_61ce91_idx",
                    ),
                    models.Index(
                        fields=["advisory", "status"],
                        name="workflows_o_advisor_41d4a5_idx",
                    ),
                ],
                "constraints": [
                    models.UniqueConstraint(
                        condition=models.Q(("status", "queued")),
                        fields=("orphan_cve",),
                        name="orphan_reassignment_one_open_per_orphan",
                    )
                ],
            },
        ),
    ]
