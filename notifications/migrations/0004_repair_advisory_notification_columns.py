"""Repair the ``notifications_advisorynotificationpreference`` columns.

Companion to ``accounts/0006_repair_notification_columns`` — catches up
databases that applied an earlier (now-rewritten) version of migration
``0002_advisorynotificationpreference_drop_watchedadvisory``, which
created the table with a single ``events_level`` enum column instead of
the three nullable lifecycle booleans the current model expects.

Idempotent: introspects the live schema and only issues ``ALTER TABLE``
for columns that are missing/extra. A fresh database (one whose 0002
already ran in its current shape) sees this as a no-op.
"""

from django.db import migrations

_TABLE = "notifications_advisorynotificationpreference"

_ADD_COLUMNS = (
    ("on_advisory_submitted_for_review", "BOOLEAN NULL"),
    ("on_advisory_published", "BOOLEAN NULL"),
    ("on_publication_export_status", "BOOLEAN NULL"),
)

_DROP_COLUMNS = ("events_level",)


def _existing_columns(schema_editor) -> set[str]:
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        return {col.name for col in connection.introspection.get_table_description(cursor, _TABLE)}


def forwards(apps, schema_editor):
    existing = _existing_columns(schema_editor)
    with schema_editor.connection.cursor() as cursor:
        for name, ddl in _ADD_COLUMNS:
            if name not in existing:
                cursor.execute(f'ALTER TABLE "{_TABLE}" ADD COLUMN "{name}" {ddl};')
        for name in _DROP_COLUMNS:
            if name in existing:
                cursor.execute(f'ALTER TABLE "{_TABLE}" DROP COLUMN "{name}";')


class Migration(migrations.Migration):
    dependencies = [("notifications", "0003_alter_advisorynotificationpreference_id")]

    operations = [migrations.RunPython(forwards, migrations.RunPython.noop)]
