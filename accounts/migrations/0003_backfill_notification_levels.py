"""Backfill ``comments_level`` from the legacy ``comment_mode`` field.

Runs between 0002 (which added ``comments_level``) and 0004 (which drops
``comment_mode``). The legacy three-way choice collapses to the new
two-way: ``"none"`` and ``"mentioned"`` both become ``"mentioned"`` (the
no-Never floor moves anyone who asked for silence to the new minimum;
mentions still always fire). ``"all"`` carries over unchanged.

The lifecycle booleans (``on_advisory_submitted_for_review``,
``on_advisory_published``, ``on_publication_export_status``) keep their
existing values — they're staying as booleans, not collapsing into a
level. No backfill needed for them.
"""

from django.db import migrations


def forwards(apps, schema_editor):
    Pref = apps.get_model("accounts", "NotificationPreference")
    for row in Pref.objects.all():
        row.comments_level = "all" if row.comment_mode == "all" else "mentioned"
        row.save(update_fields=["comments_level"])


def backwards(apps, schema_editor):
    Pref = apps.get_model("accounts", "NotificationPreference")
    for row in Pref.objects.all():
        row.comment_mode = "all" if row.comments_level == "all" else "mentioned"
        row.save(update_fields=["comment_mode"])


class Migration(migrations.Migration):
    dependencies = [("accounts", "0002_add_notification_levels")]

    operations = [migrations.RunPython(forwards, backwards)]
