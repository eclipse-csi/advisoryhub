"""Database-level append-only enforcement for audit_auditlogentry.

On Postgres (the production target), UPDATE/DELETE against the audit log
table — from the ORM, the admin, the shell, or psql — raise an exception.
The only way to remove the constraint is to drop the triggers in a
follow-up migration, captured in git history.

On other backends (SQLite for fast local tests), this migration is a
no-op: application-layer enforcement in ``AuditLogEntry.save/delete``
still applies, and the ``test_database_trigger_*`` tests skip.
"""

from django.db import migrations


CREATE_SQL = r"""
CREATE OR REPLACE FUNCTION audit_no_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit log entries are append-only (UPDATE forbidden)';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION audit_no_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit log entries are append-only (DELETE forbidden)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_auditlogentry;
DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_auditlogentry;

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_auditlogentry
    FOR EACH ROW EXECUTE FUNCTION audit_no_update();

CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit_auditlogentry
    FOR EACH ROW EXECUTE FUNCTION audit_no_delete();
"""

DROP_SQL = r"""
DROP TRIGGER IF EXISTS audit_log_no_update ON audit_auditlogentry;
DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_auditlogentry;
DROP FUNCTION IF EXISTS audit_no_update();
DROP FUNCTION IF EXISTS audit_no_delete();
"""


def _apply(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cur:
        cur.execute(CREATE_SQL)


def _reverse(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cur:
        cur.execute(DROP_SQL)


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial")]
    operations = [migrations.RunPython(_apply, _reverse)]
