from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("accounts", "0001_initial")]

    operations = [
        migrations.AddField(
            model_name="notificationpreference",
            name="comments_level",
            field=models.CharField(
                choices=[
                    ("all", "Every comment"),
                    ("mentioned", "Only when mentioned"),
                ],
                default="mentioned",
                max_length=16,
            ),
        ),
    ]
