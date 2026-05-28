"""Create the ``unsorted`` sentinel project for unrouted triage advisories.

Public intake form submissions that don't pick a real project land on this
sentinel. Its ``security_team`` is the global admin group, so admins
naturally resolve as ``owner`` via the existing project-security-team path
in :mod:`advisories.permissions` — no special-case is needed there.

The sentinel is excluded from project pickers and project listings; it
surfaces only in the triage queue under the "Unrouted" bucket.
"""

from __future__ import annotations

from django.conf import settings
from django.db import migrations


def create_unsorted_sentinel(apps, schema_editor):
    Project = apps.get_model("projects", "Project")
    Group = apps.get_model("auth", "Group")

    admin_group_name = settings.OIDC_ADMIN_GROUP
    admin_group, _ = Group.objects.get_or_create(name=admin_group_name)

    Project.objects.get_or_create(
        slug="unsorted",
        defaults={
            "name": "Unsorted reports",
            "description": (
                "Sentinel project for triage advisories submitted without a "
                "project. Admins resolve these and reassign to a real project "
                "(or dismiss) during triage."
            ),
            "security_team": admin_group,
            "is_mature_publisher": False,
        },
    )


def remove_unsorted_sentinel(apps, schema_editor):
    Project = apps.get_model("projects", "Project")
    # Only remove if no advisories still point at it.
    Advisory = apps.get_model("advisories", "Advisory")
    sentinel = Project.objects.filter(slug="unsorted").first()
    if sentinel and not Advisory.objects.filter(project=sentinel).exists():
        sentinel.delete()


class Migration(migrations.Migration):
    dependencies = [
        ("projects", "0002_ghsa_linked_advisory"),
        ("advisories", "0008_alter_advisory_state_advisoryintakemetadata"),
        ("auth", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_unsorted_sentinel, remove_unsorted_sentinel),
    ]
