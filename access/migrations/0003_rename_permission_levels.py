"""Rename permission levels: read/comment/write → viewer/collaborator.

Mapping:
    read       → viewer
    comment    → viewer  (the old `comment` level had no analogue and
                          folds back into `viewer`; viewer can now comment)
    write      → collaborator

The `owner` role is NOT represented in the model — it derives from project
security team or admin membership and is never granted via this table.

Audit log rows (`audit_auditlogentry`) are intentionally NOT rewritten: they
record what happened at the time, and editing them violates the append-only
invariant enforced by the Postgres trigger (see CLAUDE.md, "Architecture —
load-bearing rules", rule 5).
"""

from django.db import migrations, models


FORWARD_MAP = {
    "read": "viewer",
    "comment": "viewer",
    "write": "collaborator",
}

# Best-effort reverse: `viewer` → `read` (the old `comment` level is
# unrecoverable because we collapsed two values into one).
REVERSE_MAP = {
    "viewer": "read",
    "collaborator": "write",
}


def _rewrite(apps, schema_editor, mapping):
    Grant = apps.get_model("access", "AdvisoryAccessGrant")
    Invitation = apps.get_model("access", "PendingInvitation")
    for old, new in mapping.items():
        Grant.objects.filter(permission=old).update(permission=new)
        Invitation.objects.filter(permission=old).update(permission=new)


def forward(apps, schema_editor):
    _rewrite(apps, schema_editor, FORWARD_MAP)


def reverse(apps, schema_editor):
    _rewrite(apps, schema_editor, REVERSE_MAP)


class Migration(migrations.Migration):
    dependencies = [
        ("access", "0002_rename_access_principal_idx_access_advi_princip_689446_idx_and_more"),
    ]

    operations = [
        # Widen the column first so the new strings fit before we rewrite them.
        migrations.AlterField(
            model_name="advisoryaccessgrant",
            name="permission",
            field=models.CharField(
                choices=[
                    ("read", "Read"),
                    ("comment", "Comment"),
                    ("write", "Write"),
                ],
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="pendinginvitation",
            name="permission",
            field=models.CharField(
                choices=[
                    ("read", "Read"),
                    ("comment", "Comment"),
                    ("write", "Write"),
                ],
                max_length=16,
            ),
        ),
        migrations.RunPython(forward, reverse),
        # Then swap in the new choices.
        migrations.AlterField(
            model_name="advisoryaccessgrant",
            name="permission",
            field=models.CharField(
                choices=[
                    ("viewer", "Viewer"),
                    ("collaborator", "Collaborator"),
                ],
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="pendinginvitation",
            name="permission",
            field=models.CharField(
                choices=[
                    ("viewer", "Viewer"),
                    ("collaborator", "Collaborator"),
                ],
                max_length=16,
            ),
        ),
    ]
