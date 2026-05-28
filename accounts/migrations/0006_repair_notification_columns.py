"""Repair the ``accounts_notificationpreference`` columns.

This catches up databases that applied an earlier (now-rewritten) version
of migrations 0002–0004, which transiently dropped the three lifecycle
booleans and added an ``events_level`` enum column. The migration files
were later edited to keep the lifecycle booleans and not introduce
``events_level``, but DBs that ran the old shape still carry the wrong
columns — and Django's migration tracker, which only looks at file
names, can't tell.

Implementation is idempotent: it introspects the live schema and only
issues ``ALTER TABLE`` for columns that are actually missing/extra. A
fresh database (or one that never ran the transient shape) sees this
migration as a no-op. ``state_operations=[]`` is implicit because we use
``RunPython`` — the model state is already correct, only the database is
out of sync.
"""

from django.db import migrations

_TABLE = "accounts_notificationpreference"

_ADD_COLUMNS = (
    ("on_advisory_submitted_for_review", "BOOLEAN NOT NULL DEFAULT TRUE"),
    ("on_advisory_published", "BOOLEAN NOT NULL DEFAULT TRUE"),
    ("on_publication_export_status", "BOOLEAN NOT NULL DEFAULT TRUE"),
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
    dependencies = [("accounts", "0005_alter_notificationpreference_id_alter_user_groups_and_more")]

    operations = [migrations.RunPython(forwards, migrations.RunPython.noop)]
