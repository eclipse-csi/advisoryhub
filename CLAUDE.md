# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

AdvisoryHub is a **private** Django application for authoring, reviewing, publishing, and auditing security advisories for Eclipse Foundation projects. Published advisories are exported to OSV+CSAF JSON and pushed to a separate publication Git repo whose own CI/CD renders the public website. There is no public anonymous surface in this codebase.

Stack: Python 3.14, Django 5.2 LTS, PostgreSQL (required in prod — append-only audit triggers and JSON queries are Postgres-specific), Celery + Valkey (Redis-wire compatible — `redis://` URLs work unchanged), mozilla-django-oidc, server-rendered templates with HTMX.

## Specifications

Authoritative source of truth for what this system *is* and *does* lives in `docs/specification/`. Read the relevant file before making non-trivial changes; cite `INV-*` IDs in commits and PRs.

- [`docs/specification/invariant.md`](docs/specification/invariant.md) — load-bearing rules with stable `INV-*` IDs, severity tiers, enforcement file paths, and test pointers.
- [`docs/specification/architecture.md`](docs/specification/architecture.md) — tech stack, full 16-app layout, architectural patterns, publication & GHSA pipelines, Celery beat schedule, env-var inventory, operations, testing strategy.
- [`docs/specification/permissions.md`](docs/specification/permissions.md) — authorization model: actors, roles, capability matrix, state-conditioned overrides, enforcement surfaces.
- [`docs/specification/advisory-lifecycle.md`](docs/specification/advisory-lifecycle.md) — four lifecycle states plus three orthogonal sub-machines (review, CVE-request, publication-task), with transition tables and a sequence diagram.
- [`docs/specification/requirements.md`](docs/specification/requirements.md) — top-down functional spec: actors, domain objects, functional & non-functional requirements, use cases.

## Common commands

Dev environment is **docker-compose driven** and self-contained — no `.env` editing required.

```sh
# First run (mints OIDC client secret)
docker compose up -d kanidm
bash dev/kanidm/setup.sh
docker compose up

# Schema + demo data (in another terminal)
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_demo --with-publish-repo /tmp/advisoryhub-pub.git

# Reset everything
docker compose down -v && docker compose up -d kanidm && bash dev/kanidm/setup.sh && docker compose up
```

Demo login: `alice@example.org` / `correcthorsebatterystaple` (created by `dev/kanidm/setup.sh` to match `seed_demo`).

### mise (optional task runner)

[mise](https://mise.jdx.dev) wraps every command in this section. `mise trust && mise run setup` installs the bootstrap toolchain (uv + prek), syncs the locked dev env, and wires the git hooks; `mise tasks` lists them all. Each task is a thin 1:1 wrapper over the documented `uv run …` / `docker compose …` command, with `DJANGO_SETTINGS_MODULE` set per task:

- `mise run up` / `down` / `reset` — docker dev stack (`reset` wipes volumes + re-bootstraps kanidm)
- `mise run kanidm-up` / `kanidm-setup` — first-run OIDC bootstrap
- `mise run migrate` / `seed` — schema + demo data
- `mise run test` — pytest against the compose Postgres (needs `mise run up`); args pass through: `mise run test -- -k name path/`
- `mise run lint` / `fix` / `typecheck` / `ty` — ruff + mypy + advisory ty
- `mise run check` / `makemigrations-check` / `audit` — Django checks + pip-audit

mise pins only the bootstrap `uv` + `prek` (in `mise.toml`); all dev tool versions stay in `uv.lock`, the Python version in `.python-version`. CI runs these same tasks. Raw `uv`/`docker compose` commands remain canonical.

### Tests

Tests run against PostgreSQL (the same engine as prod), exercising the append-only triggers and JSONB queries. Start Postgres first (`docker compose up -d postgres` or `mise run up`). `config.settings.test` defaults to the local compose Postgres; `TEST_DATABASE_URL` overrides the host/port. `--reuse-db` (in pytest `addopts`) keeps the test DB between runs — pass `--create-db` after a migration change.

```sh
DJANGO_SETTINGS_MODULE=config.settings.test pytest          # all tests
DJANGO_SETTINGS_MODULE=config.settings.test pytest path/to/test_file.py::TestClass::test_name
TEST_DATABASE_URL=postgres://user:pass@host:5432/db \
    DJANGO_SETTINGS_MODULE=config.settings.test pytest      # custom Postgres
```

`config.settings.test` strips OIDC middleware (so `force_login` works), force-disables rate limiting and step-up, and sets `CELERY_TASK_ALWAYS_EAGER=True`. The dedicated `ratelimit_*` and step-up tests re-enable each via `@override_settings`.

### Lint

```sh
ruff check .
ruff format --check .
```

Ruff config is in `pyproject.toml` (`E,F,W,I,B,UP,DJ`, line length 100, `E501` ignored). Migrations and tests have relaxed rules; `advisories/models.py` ignores `DJ012`.

### Django management

```sh
python manage.py migrate
python manage.py makemigrations --check --dry-run     # CI also runs this
python manage.py check --deploy --fail-level WARNING
python manage.py seed_demo --with-publish-repo /tmp/pub.git
python manage.py prune_audit / forget_user            # in audit/management/commands
celery -A config worker -l info
```

### Sanity checks (prek)

`.pre-commit-config.yaml` runs the lint/format/type/Django gates above via [prek](https://github.com/j178/prek) (the Rust pre-commit drop-in). Hooks shell out through `uv run --no-sync --python .venv …`, so they use the exact `uv.lock`-pinned tools CI runs — no second place to bump versions.

```sh
mise run setup           # one-shot: installs uv+prek, syncs .venv, wires hooks
# …or by hand:
uv sync --extra dev      # provides the ruff / mypy the hooks call
uv tool install prek     # or: pipx install prek / cargo install prek / mise install
prek install             # installs BOTH the pre-commit and pre-push hooks

prek run --all-files                          # commit stage: hygiene + ruff
prek run --all-files --hook-stage pre-push    #   + mypy & Django checks
prek run --all-files --hook-stage manual      # advisory ty (mirrors CI's ty job)
```

Commit stage = file hygiene + `ruff check --fix` + `ruff format`; push stage adds `mypy`, `makemigrations --check`, and `manage.py check`. `ty` is manual + advisory (no Django plugin yet), matching CI's `continue-on-error` ty job. Vendored assets (`static/htmx.*`, `publication/schemas/*.upstream.json`, `publication/schemas/cvss/*.json`) are excluded.

## Load-bearing rules

Full catalog with stable IDs, severity tiers, and enforcement file paths in [`docs/specification/invariant.md`](docs/specification/invariant.md). Cite `INV-*` IDs in commits, PRs, and code comments. The rules that shape almost every change in this codebase:

- **`INV-LIFECYCLE-1`** — four advisory states only: `triage`, `draft`, `published`, `dismissed`. Review is orthogonal (`review_status`), not a fifth state.
- **`INV-LIFECYCLE-3`** — `state` flips to `published` only after a successful Git push. Any failure keeps the prior state and marks the `PublicationTask` `failed` with a redacted `last_error`.
- **`INV-VERSION-1`/`-2`** — `AdvisoryVersion` is append-only; content edits append v(n+1), state-only flips do not. Workflow rows (`ReviewTask`, `PublicationTask`) `PROTECT`-FK the pinned version. Adding a field to `Advisory.to_payload()` makes it versioned automatically.
- **`INV-VERSION-3`** — OSV/CSAF are built from the immutable `AdvisoryVersion` payload pinned on the task, never from live form data.
- **`INV-AUTH-1`** — authorization is server-side (views, APIs, Celery tasks); templates only display. Notification recipient lists are re-checked at *send time*.
- **`INV-AUTH-3`** — owner is derived, never assigned. `access.models.Permission.choices` excludes `owner`; services and APIs reject `permission="owner"` at the boundary.
- **`INV-AUDIT-1`** — audit log is append-only at both the application layer and a Postgres trigger.
- **`INV-AUDIT-2`** / **`INV-SECRET-1..3`** — funnel all user/CI-supplied strings through `audit.services.redact_secrets`; secrets never reach logs, audit metadata, task errors, artifact rows, or notification bodies. The publication git layer adds `publication.git_service._redact` for token-rewritten URLs.
- **`INV-OIDC-1`/`-2`** — OIDC groups are DB-mirrored on every login (`accounts.auth.AdvisoryHubOIDCBackend`); authorization always re-reads the DB mirror, never client-submitted group data. "Mature publisher" lives on the `Project` row, not on group membership.
- **`INV-INTAKE-1`/`-2`** — honeypot trips create `HoneypotSubmission`, never an `Advisory`. The public intake form has no `reporter_email` field; anonymous reports cannot be re-associated later.

## Authorization

Implemented in `advisories/permissions.py`. Three roles only, ranked `owner > collaborator > viewer`. Resolution:

1. Admin group (`OIDC_ADMIN_GROUP`) → `owner` everywhere.
2. Project security team membership → `owner` on that project's advisories.
3. Per-advisory user/group grants → `collaborator` or `viewer` (max rank across direct + group grants wins).
4. Otherwise → no access.

Publication state grants no implicit read access inside AdvisoryHub — published advisories are visible only to owners and explicit grantees (the public surface lives in the consumer Git repo's website). Editing a published advisory appends an `AdvisoryVersion` and sets `republish_required=True`.

Capability matrix per role, state-conditioned overrides (triage, admin-routing-flagged, `review_status=submitted`, published, dismissed), step-up authentication, mature-publisher gating, and enforcement surfaces are in [`docs/specification/permissions.md`](docs/specification/permissions.md).

## App layout

Sixteen Django apps under the project root. Full per-app inventory in [`docs/specification/architecture.md §2`](docs/specification/architecture.md). The apps you'll touch most:

- `advisories/` — `Advisory` (incl. `triage` state) + append-only `AdvisoryVersion` + `AdvisoryIntakeMetadata` sidecar; permissions, services (`promote_triage_to_draft`, `record_advisory_version`), forms, HTMX views.
- `access/` — `AdvisoryAccessGrant`, `PendingInvitation`, grant services.
- `audit/` — append-only `AuditLogEntry`, Postgres triggers, `redact_secrets`.
- `publication/` — OSV+CSAF builders, vendored JSON schemas in `publication/schemas/`, Git push service, Celery task.
- `workflows/` — `CveRequestTask` + `ReviewTask` state machines.
- `admin_console/` — sidebar shell at `/admin/` (Inbox, Projects, CVE, Reviews, Publication, Audit); views split into `admin_console/views/<section>.py`. Django admin itself is at `/django-admin/`.
- `intake/` — public `POST /report/` + `HoneypotSubmission` table. Triage UI lives in `advisories.views_triage`.

## Triage flow

Untrusted public submissions land in `Advisory(state=triage)` via `advisories.services.submit_triage_report`, with intake fingerprints on the `AdvisoryIntakeMetadata` sidecar. Owner-only until promoted via `promote_triage_to_draft` or dismissed via `dismiss_triage`; misrouted reports get `flag_for_admin_routing` (admin-only thereafter). Full transition table and edit side-effects in [`docs/specification/advisory-lifecycle.md §10`](docs/specification/advisory-lifecycle.md).

## Publication pipeline

Entry: `publication.services.publish(advisory, by=user)` — pins the latest `AdvisoryVersion` on a new `PublicationTask` and enqueues `publication.tasks.run_publication` via `transaction.on_commit`. Full pipeline (build OSV/CSAF, validate against vendored schemas, persist `PublicationArtifact`, clone into a fresh tempdir, write, commit, push, atomic finalisation under `select_for_update`, failure handling) in [`docs/specification/architecture.md §4`](docs/specification/architecture.md). Failed exports surface in the Admin Console's Publication page (`/admin/publications/`).

**Auth modes** for the publication repo:
- `PUB_REPO_AUTH=ssh` — `GIT_SSH_COMMAND` with `IdentitiesOnly=yes`, `BatchMode=yes`, `StrictHostKeyChecking=accept-new`. Use a pre-populated known_hosts image in prod for strict checking.
- `PUB_REPO_AUTH=token` — rewrites HTTPS URL with `https://x-access-token:$PUB_REPO_TOKEN@…`; token stripped from every error/audit/artifact/notification surface.

## Configuration

`docker-compose.yml`'s `x-django-env` anchor is the canonical dev configuration (reused by `web` and `worker`); **don't edit env files for dev**. `.env.example` documents every prod knob and is reference-only — it is *not* loaded by docker-compose. `dev/kanidm/.env.kanidm` is the only file compose actually loads at runtime (for the OIDC client secret minted by the bootstrap script).

Notable knobs: `OIDC_GROUP_CLAIM`, `OIDC_ADMIN_GROUP`, `STEP_UP_REQUIRED` (re-auth gate before publish), `READYZ_INCLUDE_PUB_REPO` (probes the pub repo as part of `/readyz`), `RATELIMIT_ENABLE`.

## Deferred / out of scope

- No public anonymous website (lives in the consumer git repo's CI output).
- No real MITRE CVE integration — `workflows.CveRequestTask` is an internal queue.
- Tests do not require a real OIDC provider, real email, or a real Git remote (Phase D tests use a temporary local bare repo and skip if `git` isn't on PATH).

## Commit policy

When creating commits in this repository, every rules bellow must be respected:

- Every commit must be signed (`-S`) and singed-off-by (`-s`).
- Every commit messages must follow the Conventional Commits specification.
- Every AI-generated commit MUST include this Git trailer in the commit message footer:

```text
Assisted-by: <AGENT_NAME>:<MODEL_VERSION>
```

Examples:

```text
Assisted-by: Codex:gpt-5.4-mini
Assisted-by: Claude:claude-sonnet-4-6
```
