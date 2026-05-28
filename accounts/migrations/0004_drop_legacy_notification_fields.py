from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("accounts", "0003_backfill_notification_levels")]

    operations = [
        migrations.RemoveField(
            model_name="notificationpreference",
            name="comment_mode",
        ),
        migrations.AlterField(
            model_name="notificationpreference",
            name="on_advisory_created",
            field=models.BooleanField(
                default=True,
                help_text=(
                    "Notify on creation of (or reassignment to) an advisory in a project "
                    "where you are on the security team. Global only — no per-advisory override."
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
                help_text="Comments on advisories you have access to.",
                max_length=16,
            ),
        ),
    ]
