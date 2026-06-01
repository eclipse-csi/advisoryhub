"""Postgres indexes that speed up advisory list filters.

* GIN index on ``aliases`` (the JSONB list of CVE/GHSA-style IDs) so
  ``aliases__icontains=CVE-2026-1234`` and friends don't sequentially
  scan the table.
* Trigram (``pg_trgm``) indexes on ``summary`` and ``details`` for
  cheap ``icontains`` searches.
"""

from django.db import migrations


CREATE_SQL = r"""
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS adv_aliases_gin
    ON advisories_advisory USING GIN (aliases jsonb_path_ops);

CREATE INDEX IF NOT EXISTS adv_summary_trgm
    ON advisories_advisory USING GIN (summary gin_trgm_ops);

CREATE INDEX IF NOT EXISTS adv_details_trgm
    ON advisories_advisory USING GIN (details gin_trgm_ops);

CREATE INDEX IF NOT EXISTS adv_advisory_id_trgm
    ON advisories_advisory USING GIN (advisory_id gin_trgm_ops);
"""

DROP_SQL = r"""
DROP INDEX IF EXISTS adv_aliases_gin;
DROP INDEX IF EXISTS adv_summary_trgm;
DROP INDEX IF EXISTS adv_details_trgm;
DROP INDEX IF EXISTS adv_advisory_id_trgm;
"""


def _apply(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute(CREATE_SQL)


def _reverse(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute(DROP_SQL)


class Migration(migrations.Migration):
    dependencies = [("advisories", "0001_initial")]
    operations = [migrations.RunPython(_apply, _reverse)]
