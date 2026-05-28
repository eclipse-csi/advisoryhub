from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion

import access.models


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        ("advisories", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AdvisoryAccessGrant",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                (
                    "principal_type",
                    models.CharField(choices=[("user", "User"), ("group", "Group")], max_length=8),
                ),
                ("principal_id", models.BigIntegerField()),
                (
                    "permission",
                    models.CharField(
                        choices=[("read", "Read"), ("comment", "Comment"), ("write", "Write")],
                        max_length=8,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "advisory",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="access_grants",
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
                "unique_together": {("advisory", "principal_type", "principal_id")},
                "indexes": [
                    models.Index(
                        fields=["principal_type", "principal_id"], name="access_principal_idx"
                    ),
                    models.Index(fields=["advisory", "permission"], name="access_adv_perm_idx"),
                ],
            },
        ),
        migrations.CreateModel(
            name="PendingInvitation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("email", models.EmailField(max_length=254)),
                (
                    "permission",
                    models.CharField(
                        choices=[("read", "Read"), ("comment", "Comment"), ("write", "Write")],
                        max_length=8,
                    ),
                ),
                (
                    "token",
                    models.CharField(default=access.models._make_token, max_length=64, unique=True),
                ),
                (
                    "expires_at",
                    models.DateTimeField(default=access.models._default_invitation_expiry),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("redeemed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "advisory",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="pending_invitations",
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
                (
                    "redeemed_by",
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
                "indexes": [
                    models.Index(fields=["email"], name="invite_email_idx"),
                    models.Index(
                        fields=["advisory", "redeemed_at"], name="invite_adv_redeemed_idx"
                    ),
                ],
            },
        ),
    ]
