"""Database-level deletion guard for advisories_advisory.

DELETE against the advisory table — from the ORM, the admin, the shell, or
psql — raises an exception. The only documented escape is
:func:`advisories.models._unsafe_dev_reset_bypass` (used by
``seed_demo --reset``), which lowers ``session_replication_role`` to
``replica`` for its transaction; that path is dev-only.
"""

from django.db import migrations


CREATE_SQL = r"""
CREATE OR REPLACE FUNCTION advisory_no_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'advisories_advisory rows are non-deletable (DELETE forbidden)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS advisory_no_delete ON advisories_advisory;

CREATE TRIGGER advisory_no_delete
    BEFORE DELETE ON advisories_advisory
    FOR EACH ROW EXECUTE FUNCTION advisory_no_delete();
"""

DROP_SQL = r"""
DROP TRIGGER IF EXISTS advisory_no_delete ON advisories_advisory;
DROP FUNCTION IF EXISTS advisory_no_delete();
"""


def _apply(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute(CREATE_SQL)


def _reverse(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute(DROP_SQL)


class Migration(migrations.Migration):
    dependencies = [("advisories", "0006_ghsa_linked_advisory")]
    operations = [migrations.RunPython(_apply, _reverse)]
