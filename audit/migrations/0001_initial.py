from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("advisories", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="AuditLogEntry",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("advisory.created", "Advisory Created"),
                            ("advisory.viewed", "Advisory Viewed"),
                            ("advisory.edited", "Advisory Edited"),
                            ("advisory.state_changed", "Advisory State Changed"),
                            ("advisory.project_changed", "Advisory Project Changed"),
                            ("advisory.submitted_for_review", "Advisory Submitted For Review"),
                            ("advisory.review_approved", "Advisory Review Approved"),
                            ("advisory.review_rejected", "Advisory Review Rejected"),
                            (
                                "advisory.review_changes_requested",
                                "Advisory Review Changes Requested",
                            ),
                            ("advisory.published", "Advisory Published"),
                            ("advisory.dismissed", "Advisory Dismissed"),
                            ("access.granted", "Access Granted"),
                            ("access.revoked", "Access Revoked"),
                            ("invitation.created", "Invitation Created"),
                            ("invitation.redeemed", "Invitation Redeemed"),
                            ("comment.created", "Comment Created"),
                            ("comment.edited", "Comment Edited"),
                            ("comment.redacted", "Comment Redacted"),
                            ("cve.requested", "Cve Requested"),
                            ("cve.task_status_changed", "Cve Task Status Changed"),
                            ("review.task_status_changed", "Review Task Status Changed"),
                            ("publication.export_started", "Publication Export Started"),
                            ("publication.export_completed", "Publication Export Completed"),
                            ("publication.export_failed", "Publication Export Failed"),
                            ("publication.osv_generated", "Publication Osv Generated"),
                            ("publication.csaf_generated", "Publication Csaf Generated"),
                            ("publication.git_commit", "Publication Git Commit"),
                            ("publication.git_push", "Publication Git Push"),
                            ("publication.git_push_failed", "Publication Git Push Failed"),
                            ("notification.prefs_changed", "Notification Prefs Changed"),
                        ],
                        max_length=64,
                    ),
                ),
                ("comment_id", models.BigIntegerField(blank=True, null=True)),
                ("previous_value", models.JSONField(blank=True, null=True)),
                ("new_value", models.JSONField(blank=True, null=True)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.CharField(blank=True, max_length=512)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "advisory",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="audit_entries",
                        to="advisories.advisory",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["created_at"], name="audit_audit_created_idx"),
                    models.Index(fields=["advisory", "created_at"], name="audit_audit_adv_idx"),
                    models.Index(fields=["actor", "created_at"], name="audit_audit_actor_idx"),
                    models.Index(fields=["action"], name="audit_audit_action_idx"),
                ],
            },
        ),
    ]
