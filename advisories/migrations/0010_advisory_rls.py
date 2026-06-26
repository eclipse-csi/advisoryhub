"""Row-level-security backstop for advisory visibility (INV-CONF-2).

Enables RLS on ``advisories_advisory`` with a policy that mirrors
``advisories.permissions.visible_advisories`` / ``AdvisoryQuerySet.visible_to``,
keyed on the ``advisoryhub.user_id`` / ``advisoryhub.is_admin`` session GUCs set
by ``common.rls`` (``RowLevelSecurityMiddleware`` + the
``rls_principal`` / ``rls_system`` context managers). Content child tables defer
to the advisory policy via an ``EXISTS`` over the (already RLS-filtered)
``advisories_advisory``.

The tables the advisory predicate itself reads — ``access_advisoryaccessgrant``,
``projects_project``, ``accounts_user_groups`` — are deliberately left RLS-free
so the policy cannot recurse. The append-only audit tables
(``audit_auditlogentry`` / ``audit_accesslogentry``) are the global timeline
([INV-AUDIT-1], admin-only reads, written by every user action) and are
deliberately excluded. Workflow / publication / notification / similarity / GHSA
child tables are left to the application layer in this iteration.

Enforced only for a non-superuser DB role: the dev/CI bootstrap role is a
superuser (RLS-exempt), so this is dormant there and active under the production
non-superuser app role (running-in-production §7). ``FORCE`` covers the case
where that role also owns the tables.
"""

from django.db import migrations

# Direct ``advisory_id``-FK content children that inherit advisory visibility.
_CHILD_TABLES = [
    "advisories_advisoryversion",
    "advisories_advisoryintakemetadata",
    "advisories_advisoryvisit",
    "comments_advisorycomment",
]

_ADVISORY_POLICY = r"""
ALTER TABLE advisories_advisory ENABLE ROW LEVEL SECURITY;
ALTER TABLE advisories_advisory FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS advisory_visibility ON advisories_advisory;
CREATE POLICY advisory_visibility ON advisories_advisory
    FOR ALL
    USING (
        current_setting('advisoryhub.is_admin', true) = 'on'
        OR EXISTS (
            SELECT 1
            FROM accounts_user_groups uug
            JOIN projects_project p ON p.security_team_id = uug.group_id
            WHERE uug.user_id = NULLIF(current_setting('advisoryhub.user_id', true), '')::bigint
              AND p.id = advisories_advisory.project_id
        )
        OR EXISTS (
            SELECT 1
            FROM access_advisoryaccessgrant g
            WHERE g.advisory_id = advisories_advisory.id
              AND (
                  (g.principal_type = 'user'
                   AND g.principal_id = NULLIF(current_setting('advisoryhub.user_id', true), '')::bigint)
                  OR (g.principal_type = 'group'
                      AND g.principal_id IN (
                          SELECT group_id FROM accounts_user_groups
                          WHERE user_id = NULLIF(current_setting('advisoryhub.user_id', true), '')::bigint))
              )
        )
    )
    WITH CHECK (true);
"""

_DROP_ADVISORY = r"""
DROP POLICY IF EXISTS advisory_visibility ON advisories_advisory;
ALTER TABLE advisories_advisory NO FORCE ROW LEVEL SECURITY;
ALTER TABLE advisories_advisory DISABLE ROW LEVEL SECURITY;
"""


def _child_apply_sql(table: str) -> str:
    return f"""
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS advisory_child_visibility ON {table};
CREATE POLICY advisory_child_visibility ON {table}
    FOR ALL
    USING (EXISTS (SELECT 1 FROM advisories_advisory a WHERE a.id = {table}.advisory_id))
    WITH CHECK (true);
"""


def _child_drop_sql(table: str) -> str:
    return f"""
DROP POLICY IF EXISTS advisory_child_visibility ON {table};
ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;
ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;
"""


def _apply(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cur:
        cur.execute(_ADVISORY_POLICY)
        for table in _CHILD_TABLES:
            cur.execute(_child_apply_sql(table))


def _reverse(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cur:
        for table in _CHILD_TABLES:
            cur.execute(_child_drop_sql(table))
        cur.execute(_DROP_ADVISORY)


class Migration(migrations.Migration):
    dependencies = [
        ("advisories", "0009_advisory_severity_level_severity_score"),
        ("access", "0001_initial"),
        ("comments", "0001_initial"),
        ("projects", "0001_initial"),
        ("accounts", "0001_initial"),
    ]
    operations = [migrations.RunPython(_apply, _reverse)]
