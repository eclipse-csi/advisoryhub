# Maintenance & operations

Day-2 operations: backups, upgrades, the maintenance-mode switch, the
management-command reference, and data retention / GDPR.

Management commands run from the same image as the app, with the production
settings and environment, as one-off invocations — e.g.
`DJANGO_SETTINGS_MODULE=config.settings.prod python manage.py <command>` (via a
container `exec`, a Kubernetes `Job`, etc.).

---

## 1. Backups & data integrity

**PostgreSQL is the only stateful store you must back up.** Everything durable —
advisories, versions, the audit log, grants, workflow state — lives there.

- Use your platform's standard PostgreSQL backup (managed snapshots, `pg_dump`,
  or WAL archiving). A logical `pg_dump`/restore is fine; the schema's protective
  triggers are recreated by migrations.
- **Append-only protections are enforced in the database**, not just the app: the
  audit log rejects `UPDATE`/`DELETE` and `Advisory` rejects `DELETE`, even via raw
  SQL ([INV-AUDIT-1](../specification/invariant.md#inv-audit-1)). The controlled maintenance commands below use a scoped,
  audited bypass; ordinary access cannot mutate history.

**Valkey / Redis is ephemeral** — it holds the Celery broker queue and the cache.
You do not back it up. On loss, the cache simply rebuilds; *queued-but-not-started*
tasks can be lost (in-flight tasks redeliver thanks to `acks_late`), but no durable
state is affected because outcomes live on domain rows in Postgres.

**The publication Git repository is external and self-authoritative** for the
public output — it is backed up by its own hosting, not by AdvisoryHub. If history
is ever lost there, re-publishing regenerates and re-pushes the current advisories.

---

## 2. Upgrades

1. **Dependencies / Python.** Bump `.python-version` and/or `uv.lock` and **rebuild
   the image** (`down -v` keeps cached images, so rebuild explicitly after a
   `Dockerfile`/lockfile change).
2. **Pre-deploy gates** — run these (the CI pipeline runs the same; mirror them in
   your release pipeline):
   ```sh
   python manage.py makemigrations --check --dry-run     # fail if a migration is missing
   python manage.py check --deploy --fail-level WARNING  # deploy-readiness checks
   pip-audit                                             # known-vuln scan
   ```
   The `mise` wrappers are `mise run makemigrations-check`, `mise run check`,
   `mise run audit`.
3. **Apply migrations** during the release: `python manage.py migrate`.
4. **Roll** the web/worker/beat processes. Note that changing a cookie name (rare,
   flagged in the settings) logs every user out once on that deploy.

CI additionally runs the test suite against PostgreSQL, `ruff`, `mypy`, an advisory
`ty` pass, and the vendored-asset/template guards — see `.github/workflows/`.

**Vendored assets** (htmx, Inter, ALTCHA, the docs CSS, and the OSV/CSAF/CVE JSON
schemas) are version-tracked by a scoped, self-hosted **Renovate** workflow
(`.github/workflows/renovate.yml`), separate from Dependabot. It needs a GitHub App
installed on the repo: set repo **variable** `RENOVATE_APP_ID` and **secret**
`RENOVATE_APP_PRIVATE_KEY` (App permissions: contents, pull-requests, issues — all
write). Schema PRs auto-merge on green CI; frontend-asset PRs are review-only (manual
smoke). The same workflow also bumps the `mise.toml` tool pins (grouped, review-only).
Trigger an on-demand or `dryRun` pass from the Actions tab; re-vendor locally
with `mise run update-vendor`. See
[contributing §6](../contributing/README.md#6-code-quality).

Cutting a **release** (version-lockstep bump, signed tag, container image to
ghcr.io, Helm chart publish) is its own tag-driven pipeline — runbook in
[`docs/contributing/releasing.md`](../contributing/releasing.md).

---

## 3. Maintenance mode

For a quiet window (migrations, data work), a global admin toggles **maintenance
mode** from the Admin Console at `/admin/maintenance/`. It is a DB-backed flag read
on every write attempt, so the pause is coherent across all replicas the instant it
is toggled ([INV-MAINT-1](../specification/invariant.md#inv-maint-1)).

While on:

- **Non-admin state-changing requests** (POST/PATCH/DELETE) are refused server-side
  with `503` + `Retry-After: 3600`; **reads continue** so users still see the
  banner.
- **Global admins are never paused** — they can keep working (e.g. to finish the
  task and lift the pause).
- A short list of paths stays open for everyone: `/oidc/` (sign-in/out),
  `/healthz`, `/readyz`, `/metrics`, `/static/`, and the HMAC-verified
  `/ghsa/webhook/`.

Maintenance mode gates the **web tier only**. If you need *no* background processing
during the window (e.g. an exclusive migration), stop or scale down the `worker`
and `beat` processes too.

---

## 4. Management-command reference

Project-specific commands (Django's own `migrate`, `collectstatic`, `check`,
`makemigrations` are used as normal):

| Command | App | Purpose | Key flags |
|---|---|---|---|
| `prune_audit` | audit | Delete audit-log entries older than the horizon (uses the controlled append-only bypass; records the sweep on an `AUDIT_PRUNED` entry). | `--older-than-days N` (default 3650 ≈ 10y), `--dry-run`, `--reason TEXT` |
| `forget_user` | audit | GDPR right-to-be-forgotten: anonymise a user across audit, comments, and invitations. | `email` (positional), `--pseudo EMAIL`, `--reason TEXT`, `--also-delete` |
| `maintain_access_log_partitions` | audit | Manual run of the daily task: create the upcoming access-log partition, drop expired ones. | `--retention-days N`, `--dry-run` |
| `prune_reports` | intake | Scrub PII (IP, user-agent, reporter name) from old triage intake sidecars + honeypot rows. | `--dry-run`, `--advisory-id ID` (one-off), `--retention-days N` |
| `sync_roster` | projects | Refresh security-team rosters from the authenticated Eclipse API (shadow-user provisioning). | `--all`, `--project SLUG`, `--actor EMAIL` |
| `sync_ghsa` | ghsa | Sync the PMI repo mirror and/or GHSA-linked advisory metadata. | `--all`, `--project SLUG`, `--advisory ID`, `--pmi-only`, `--actor EMAIL` |
| `discover_github_installations` | ghsa | Populate the GitHub App installation registry (run once after enabling GHSA, or to recover after webhook loss). | `--actor EMAIL` |
| `backfill_fingerprints` | similarity | Generate missing/stale duplicate-detection fingerprints for existing advisories (run once after enabling `SIMILARITY_CHECK_ENABLED`; refuses to run while it is off). One LLM call per advisory; idempotent. | `--dry-run`, `--limit N` (0 = no limit), `--project SLUG` |
| `seed_demo` | admin_console | **Dev-only.** Seed demo projects/users/advisories. Destructive with `--reset`; never run in prod. | `--reset`, `--with-publish-repo PATH` |

---

## 5. Data retention & GDPR

AdvisoryHub minimises retained personal data through scheduled jobs and on-demand
commands:

- **Access log** — monthly partitions older than `AUDIT_ACCESS_LOG_RETENTION_DAYS`
  (default 90) are dropped by the daily `maintain_access_log_partitions` task (run
  it by hand with the command above). Controlled by
  `AUDIT_ACCESS_LOG_RETENTION_ENABLED`.
- **Intake PII** — reporter IP/user-agent/name on triage sidecars and honeypot rows
  are scrubbed after `INTAKE_REPORT_RETENTION_DAYS` (default 365) via `prune_reports`;
  use `--advisory-id` for a one-off erasure request.
- **Audit ledger** — `prune_audit` trims entries past a long horizon (default ~10
  years), honouring the append-only trigger via its controlled bypass and
  recording the sweep itself on an `AUDIT_PRUNED` audit entry (horizon, cutoff,
  deleted count). After a sweep, affected advisories' activity timelines and the
  Admin Console's Audit-logs page show a marker noting that older audit events
  were removed (the *retention floor*), so a truncated history is not mistaken
  for a short one.
- **Right to be forgotten** — `forget_user` pseudonymises a specific person across
  the system (optionally deleting the row), recording the justification on a
  `USER_FORGOTTEN` audit entry.

---

## Related pages

- [running-in-production.md](./running-in-production.md) — the beat schedule that drives the retention tasks.
- [configuration.md](./configuration.md) — the retention and intake variables.
- [installation.md](./installation.md) — first-run and the dev `seed_demo` flow.
