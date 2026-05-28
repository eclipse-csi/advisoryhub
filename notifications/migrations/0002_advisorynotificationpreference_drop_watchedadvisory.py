from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("advisories", "0001_initial"),
        ("notifications", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AdvisoryNotificationPreference",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                (
                    "on_advisory_submitted_for_review",
                    models.BooleanField(blank=True, default=None, null=True),
                ),
                (
                    "on_advisory_published",
                    models.BooleanField(blank=True, default=None, null=True),
                ),
                (
                    "on_publication_export_status",
                    models.BooleanField(blank=True, default=None, null=True),
                ),
                (
                    "comments_level",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("all", "Every comment"),
                            ("mentioned", "Only when mentioned"),
                        ],
                        default="",
                        max_length=16,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "advisory",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notification_preferences",
                        to="advisories.advisory",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="advisory_notification_preferences",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "unique_together": {("user", "advisory")},
                "indexes": [
                    models.Index(fields=["advisory"], name="adv_notif_pref_adv_idx"),
                ],
            },
        ),
        migrations.DeleteModel(name="WatchedAdvisory"),
    ]
