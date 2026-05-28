from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion

import advisories.validators


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        ("projects", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Advisory",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                (
                    "advisory_id",
                    models.CharField(
                        max_length=32,
                        unique=True,
                        validators=[advisories.validators.validate_advisory_id],
                    ),
                ),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("draft", "Draft"),
                            ("published", "Published"),
                            ("dismissed", "Dismissed"),
                        ],
                        default="draft",
                        max_length=16,
                    ),
                ),
                (
                    "review_status",
                    models.CharField(
                        choices=[
                            ("none", "Not submitted"),
                            ("submitted", "Submitted for review"),
                            ("changes_requested", "Changes requested"),
                            ("approved", "Approved"),
                            ("rejected", "Rejected"),
                        ],
                        default="none",
                        max_length=24,
                    ),
                ),
                ("submitted_for_review_at", models.DateTimeField(blank=True, null=True)),
                ("summary", models.CharField(blank=True, max_length=300)),
                ("details", models.TextField(blank=True)),
                (
                    "aliases",
                    models.JSONField(
                        blank=True,
                        default=list,
                        validators=[advisories.validators.validate_aliases],
                    ),
                ),
                (
                    "references",
                    models.JSONField(
                        blank=True,
                        default=list,
                        validators=[advisories.validators.validate_references],
                    ),
                ),
                (
                    "affected",
                    models.JSONField(
                        blank=True,
                        default=list,
                        validators=[advisories.validators.validate_affected],
                    ),
                ),
                (
                    "severity",
                    models.JSONField(
                        blank=True,
                        default=list,
                        validators=[advisories.validators.validate_severity],
                    ),
                ),
                (
                    "cwe_ids",
                    models.JSONField(
                        blank=True,
                        default=list,
                        validators=[advisories.validators.validate_cwe_ids],
                    ),
                ),
                (
                    "credits",
                    models.JSONField(
                        blank=True,
                        default=list,
                        validators=[advisories.validators.validate_credits],
                    ),
                ),
                ("published_at", models.DateTimeField(blank=True, null=True)),
                ("modified_at", models.DateTimeField(auto_now=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("withdrawn_reason", models.TextField(blank=True)),
                ("dismissed_reason", models.TextField(blank=True)),
                ("republish_required", models.BooleanField(default=False)),
                (
                    "created_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="advisories",
                        to="projects.project",
                    ),
                ),
                (
                    "submitted_for_review_by",
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
                    models.Index(fields=["state"], name="adv_state_idx"),
                    models.Index(fields=["project", "state"], name="adv_proj_state_idx"),
                    models.Index(fields=["review_status"], name="adv_review_idx"),
                ],
            },
        ),
        migrations.CreateModel(
            name="AdvisorySnapshot",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                (
                    "kind",
                    models.CharField(
                        choices=[("review", "Review"), ("publication", "Publication")],
                        max_length=16,
                    ),
                ),
                ("payload", models.JSONField()),
                ("osv_json", models.JSONField(blank=True, null=True)),
                ("csaf_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "advisory",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="snapshots",
                        to="advisories.advisory",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
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
                    models.Index(fields=["advisory", "kind", "created_at"], name="adv_snap_idx")
                ],
            },
        ),
    ]
