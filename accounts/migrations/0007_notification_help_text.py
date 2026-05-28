from django.db import migrations, models


class Migration(migrations.Migration):
    """Refresh ``help_text`` on every ``NotificationPreference`` field.

    Metadata-only — no DDL is emitted by these ``AlterField`` operations.
    Shipped explicitly so ``makemigrations --check`` stays clean.
    """

    dependencies = [("accounts", "0006_repair_notification_columns")]

    operations = [
        migrations.AlterField(
            model_name="notificationpreference",
            name="on_advisory_created",
            field=models.BooleanField(
                default=True,
                help_text=(
                    "When an advisory is created in (or reassigned to) a project where "
                    "you're on the security team. Global only — no per-advisory override."
                ),
            ),
        ),
        migrations.AlterField(
            model_name="notificationpreference",
            name="on_advisory_submitted_for_review",
            field=models.BooleanField(
                default=True,
                help_text="When an advisory you have access to is submitted for review.",
            ),
        ),
        migrations.AlterField(
            model_name="notificationpreference",
            name="on_advisory_published",
            field=models.BooleanField(
                default=True,
                help_text="When an advisory you have access to is published to the public repo.",
            ),
        ),
        migrations.AlterField(
            model_name="notificationpreference",
            name="on_publication_export_status",
            field=models.BooleanField(
                default=True,
                help_text=(
                    "When the publication export succeeds or fails — useful for security-team "
                    "members responsible for the publication pipeline."
                ),
            ),
        ),
        migrations.AlterField(
            model_name="notificationpreference",
            name="comments_level",
            field=models.CharField(
                choices=[
                    ("all", "Every comment"),
                    ("mentioned", "Only when mentioned"),
                ],
                default="mentioned",
                help_text=(
                    "Mentions are always delivered. Pick whether non-mention comments also "
                    "notify you."
                ),
                max_length=16,
            ),
        ),
    ]
