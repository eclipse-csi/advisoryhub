from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("advisories", "0002_alias_search_indexes"),
    ]

    operations = [
        migrations.AddField(
            model_name="advisory",
            name="access_review_required_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
