import uuid

import django.db.models.deletion
from django.core.validators import RegexValidator
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [("auth", "0012_alter_user_first_name_max_length")]

    operations = [
        migrations.CreateModel(
            name="Project",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        primary_key=True,
                        default=uuid.uuid4,
                        editable=False,
                        serialize=False,
                    ),
                ),
                (
                    "slug",
                    models.CharField(
                        max_length=100,
                        unique=True,
                        help_text="Eclipse Foundation PMI project id (e.g. 'technology.jetty').",
                        validators=[
                            RegexValidator(
                                regex=r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$",
                                message=(
                                    "Must be a valid Eclipse Foundation PMI project id "
                                    "(lowercase letters, digits, '.', '-', '_'; "
                                    "e.g. 'technology.jetty')."
                                ),
                            )
                        ],
                    ),
                ),
                ("name", models.CharField(max_length=200)),
                ("description", models.TextField(blank=True)),
                ("homepage_url", models.URLField(blank=True)),
                (
                    "is_mature_publisher",
                    models.BooleanField(
                        default=False,
                        help_text="If true, members of the security team can publish advisories without top-level review.",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "security_team",
                    models.ForeignKey(
                        help_text="Group whose members are the project's security team.",
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="projects_secured",
                        to="auth.group",
                    ),
                ),
            ],
            options={"ordering": ["name"]},
        ),
    ]
