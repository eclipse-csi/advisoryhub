from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        ("advisories", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="PublicationTask",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("running", "Running"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                        ],
                        default="queued",
                        max_length=16,
                    ),
                ),
                ("attempts", models.PositiveIntegerField(default=0)),
                ("last_error", models.TextField(blank=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("celery_task_id", models.CharField(blank=True, max_length=64)),
                ("commit_sha", models.CharField(blank=True, max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "advisory",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="publication_tasks",
                        to="advisories.advisory",
                    ),
                ),
                (
                    "enqueued_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "snapshot",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="publication_tasks",
                        to="advisories.advisorysnapshot",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["status", "created_at"], name="pub_status_idx"),
                    models.Index(fields=["advisory", "status"], name="pub_adv_status_idx"),
                ],
            },
        ),
        migrations.CreateModel(
            name="PublicationArtifact",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                (
                    "kind",
                    models.CharField(choices=[("osv", "OSV"), ("csaf", "CSAF")], max_length=8),
                ),
                ("path", models.CharField(max_length=255)),
                ("content", models.JSONField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "task",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="artifacts",
                        to="publication.publicationtask",
                    ),
                ),
            ],
            options={
                "unique_together": {("task", "kind")},
                "ordering": ["task", "kind"],
            },
        ),
        migrations.CreateModel(
            name="PublicationRepositoryConfig",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("name", models.SlugField(max_length=64, unique=True)),
                ("is_active", models.BooleanField(default=False)),
                ("repo_url", models.CharField(max_length=512)),
                ("branch", models.CharField(default="main", max_length=128)),
                (
                    "auth_method",
                    models.CharField(
                        choices=[("ssh", "SSH key"), ("token", "HTTPS token")],
                        default="ssh",
                        max_length=8,
                    ),
                ),
                ("ssh_key_path", models.CharField(blank=True, max_length=512)),
                ("token", models.CharField(blank=True, max_length=512)),
                ("commit_author_name", models.CharField(max_length=200)),
                ("commit_author_email", models.EmailField(max_length=254)),
                (
                    "osv_path_template",
                    models.CharField(default="osv/{advisory_id}.json", max_length=255),
                ),
                (
                    "csaf_path_template",
                    models.CharField(default="csaf/{advisory_id}.json", max_length=255),
                ),
            ],
            options={"verbose_name": "publication repository config"},
        ),
    ]
