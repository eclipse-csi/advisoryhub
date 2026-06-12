# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

AdvisoryHub is a **private** Django application for authoring, reviewing, publishing, and auditing security advisories for Eclipse Foundation projects. Published advisories are exported to OSV+CSAF JSON and pushed to a separate publication Git repo whose own CI/CD renders the public website. There is no public anonymous surface in this codebase.

Stack: Python 3.14, Django 5.2 LTS, PostgreSQL (required in prod — append-only audit triggers and JSON queries are Postgres-specific), Celery + Valkey (Redis-wire compatible — `redis://` URLs work unchanged), mozilla-django-oidc, server-rendered templates with HTMX.

## Specifications

The specification set in `docs/specification/` is the **single source of truth** for what this system *is* and *does* (verified against the code and aligned on 2026-06-11). All development MUST conform to it:

- Read the relevant file before making non-trivial changes; cite `INV-*` IDs in commits and PRs.
- Any deviation from the spec requires **explicit maintainer confirmation before implementation** — never silently implement behavior the spec contradicts or forbids.
- Every behavior change must update the affected spec file(s) **in the same commit/PR**; a code/spec mismatch is a defect in whichever side drifted.

- [`docs/specification/invariant.md`](docs/specification/invariant.md) — load-bearing rules with stable `INV-*` IDs, severity tiers, enforcement file paths, and test pointers.
- [`docs/specification/architecture.md`](docs/specification/architecture.md) — tech stack, full app layout, architectural patterns, publication & GHSA pipelines, Celery beat schedule, env-var inventory, operations, testing strategy.
- [`docs/specification/permissions.md`](docs/specification/permissions.md) — authorization model: actors, roles, capability matrix, state-conditioned overrides, enforcement surfaces.
- [`docs/specification/advisory-lifecycle.md`](docs/specification/advisory-lifecycle.md) — four lifecycle states plus three orthogonal sub-machines (review, CVE-request, publication-task), with transition tables and a sequence diagram.
- [`docs/specification/requirements.md`](docs/specification/requirements.md) — top-down functional spec: actors, domain objects, functional & non-functional requirements, use cases.
- [`docs/specification/openapi.yaml`](docs/specification/openapi.yaml) — OpenAPI 3.0 contract for the machine-consumable endpoints (`/api/`, GHSA webhook, intake project picker, health probes), rendered on the docs site by [`docs/specification/api.md`](docs/specification/api.md); drift-guarded against the URLconf by `api/tests/test_openapi_spec.py`, `info.version` release-lockstepped by `dev/release.sh` / `dev/check_release_versions.sh`.

## Common commands

Dev environment is **docker-compose driven** and self-contained — no `.env` editing required.

```sh
# One time: the app images base on Docker Hardened Images (free Docker account)
docker login dhi.io

# First run (mints OIDC client secret)
docker compose up -d kanidm
bash dev/kanidm/setup.sh
docker compose up

# Schema + demo data (in another terminal)
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_demo --with-publish-repo /tmp/advisoryhub-pub.git

# Reset everything (down -v drops volumes but keeps cached images — rebuild
# so a changed Dockerfile / uv.lock, e.g. a Python bump, is actually picked up)
docker compose down -v && docker compose build && docker compose up -d kanidm && bash dev/kanidm/setup.sh && docker compose up
```

Demo login: `alice@example.org` / `correcthorsebatterystaple` (created by `dev/kanidm/setup.sh` to match `seed_demo`).

### mise (optional task runner)

[mise](https://mise.jdx.dev) wraps every command in this section. `mise trust && mise run setup` installs the bootstrap toolchain (uv + prek), syncs the locked dev env, and wires the git hooks; `mise tasks` lists them all. Each task is a thin 1:1 wrapper over the documented `uv run …` / `docker compose …` command, with `DJANGO_SETTINGS_MODULE` set per task:

- `mise run up` / `down` / `build` / `reset` — docker dev stack (`reset` wipes volumes, rebuilds images, and re-bootstraps kanidm; `build` rebuilds the web/worker images alone — needed after a Dockerfile/dependency change, since `down -v` keeps cached images)
- `mise run kanidm-up` / `kanidm-setup` — first-run OIDC bootstrap
- `mise run migrate` / `seed` — schema + demo data
- `mise run test` — pytest against the compose Postgres (needs `mise run up`); args pass through: `mise run test -- -k name path/`
- `mise run lint` / `fix` / `typecheck` / `ty` — ruff + mypy + advisory ty
- `mise run check` / `makemigrations-check` / `audit` — Django checks + pip-audit
- `mise run verify-vendor` / `check-templates` — vendored-asset checksum + template-comment guards (also run by prek/CI)
- `mise run helm-lint` / `helm-template` / `helm-validate` / `verify-chart-assets` — Helm chart gates for `charts/advisoryhub` (lint + kubeconform render validation + observability-asset sync; also run by CI)
- `mise run zizmor` — security-audit the GitHub Actions workflows (also run by prek + CI's workflow-security job; config in `.github/zizmor.yml`)
- `mise run release` / `release-check` / `changelog` / `sbom` — cut a release / version-consistency gate / git-cliff notes / CycloneDX SBOM (see [Releases](#releases))
- `mise run docs-build` / `docs-serve` / `docs-deploy` — strict docs build / live preview on :8001 / mike deploy into the LOCAL gh-pages branch (CI: `.github/workflows/docs.yml` publishes versioned docs to GitHub Pages)

mise pins only the bootstrap `uv` + `prek` (in `mise.toml`) plus the chart/release binaries (`helm`, `kubeconform`, `git-cliff`, `trivy`); all dev tool versions stay in `uv.lock`, the Python version in `.python-version`. CI runs these same tasks. Raw `uv`/`docker compose` commands remain canonical.

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
prek run --all-files --hook-stage pre-push    #   + mypy, Django checks & pip-audit
prek run --all-files --hook-stage manual      # advisory ty (mirrors CI's ty job)
```

Commit stage = file hygiene + `ruff check --fix` + `ruff format`, plus three repo guards: `dev/check_vendored_assets.sh` (htmx + Inter font sha256 vs their `*.VERSION` files), `dev/check_template_comments.py` (rejects multi-line `{# #}` — Django's single-line comment renders those as literal text), and zizmor (workflow security audit, fires when `.github/` workflow files change). Push stage adds `mypy`, `makemigrations --check`, `manage.py check`, and `pip-audit` (dependency audit, mirrors CI's security job; needs network). `ty` is manual + advisory (no Django plugin yet), matching CI's `continue-on-error` ty job. Vendored/verbatim assets (`static/htmx.*`, `static/fonts/*.woff2`, `static/fonts/Inter.VERSION`, `publication/schemas/*.upstream.json`, `publication/schemas/cvss/*.json`) are excluded from the hygiene hooks.

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
- **`INV-OIDC-5`/`INV-ROSTER-1`** — the security-team roster sync (`projects.services.sync_security_team_roster`, off unless `PMI_ROSTER_SYNC_ENABLED`) pre-provisions notification-only *shadow* users (`User.is_provisioned=True`) so `@team` mentions reach members who've never logged in. Shadows are in **no** group, hold **no** authorization, and are cleared to real users on first login; the roster sync never writes `user.groups`.
- **`INV-INTAKE-1`/`-2`** — honeypot trips create `HoneypotSubmission`, never an `Advisory`. The public intake form has no `reporter_email` field; anonymous reports cannot be re-associated later.
- **`INV-MAINT-1`** — while maintenance mode is on, only global admins may mutate state; every other user's writes are paused server-side (`common.middleware.MaintenanceModeMiddleware`), toggled from the Admin Console's Maintenance page.

## Authorization

Implemented in `advisories/permissions.py`. Three roles only, ranked `owner > collaborator > viewer`. Resolution:

1. Admin group (`OIDC_ADMIN_GROUP`) → `owner` everywhere.
2. Project security team membership → `owner` on that project's advisories.
3. Per-advisory user/group grants → `collaborator` or `viewer` (max rank across direct + group grants wins).
4. Otherwise → no access.

Publication state grants no implicit read access inside AdvisoryHub — published advisories are visible only to owners and explicit grantees (the public surface lives in the consumer Git repo's website). Editing a published advisory appends an `AdvisoryVersion` and sets `republish_required=True`.

Capability matrix per role, state-conditioned overrides (triage, admin-routing-flagged, `review_status=submitted`, published, dismissed), step-up authentication, mature-publisher gating, and enforcement surfaces are in [`docs/specification/permissions.md`](docs/specification/permissions.md).

## App layout

Fourteen Django apps under the project root (plus the `config` project package and the `common` helper module, which are not installed apps). Full per-app inventory in [`docs/specification/architecture.md §2`](docs/specification/architecture.md). The apps you'll touch most:

- `advisories/` — `Advisory` (incl. `triage` state) + append-only `AdvisoryVersion` + `AdvisoryIntakeMetadata` sidecar; permissions, services (`promote_triage_to_draft`, `record_advisory_version`), forms, HTMX views.
- `access/` — `AdvisoryAccessGrant`, `PendingInvitation`, grant services.
- `audit/` — append-only `AuditLogEntry`, Postgres triggers, `redact_secrets`.
- `publication/` — OSV+CSAF builders, vendored JSON schemas in `publication/schemas/`, Git push service, Celery task.
- `workflows/` — `CveRequestTask` + `ReviewTask` state machines.
- `admin_console/` — sidebar shell at `/admin/` (Inbox, Projects, Users, Groups, CVE Assignment, Publication, Audit logs, Access log, Maintenance — review decisions happen on the advisory page, surfaced via the Inbox); views split into `admin_console/views/<section>.py`. Django admin itself is at `/django-admin/`.
- `intake/` — public `POST /report/` + `HoneypotSubmission` table. Triage UI lives in `advisories.views` (promote / dismiss / flag / reassign).
- `similarity/` — LLM-assisted duplicate detection: `SimilarityCheck`/`SimilarityCandidate` task rows + `AdvisoryFingerprint` cache, Postgres prefilter + provider-agnostic LLM judge (`similarity/llm/` — Anthropic or any OpenAI-compatible endpoint, raw `requests`), owner-only HTMX panel on the advisory page, `backfill_fingerprints` command. Dormant unless `SIMILARITY_CHECK_ENABLED` (INV-SIM-2: enabling it is the consent for advisory content to reach the LLM provider).

## Triage flow

Untrusted public submissions land in `Advisory(state=triage)` via `advisories.services.submit_triage_report`, with intake fingerprints on the `AdvisoryIntakeMetadata` sidecar. Owner-only until promoted via `promote_triage_to_draft` or dismissed via `dismiss_triage`; misrouted reports get `flag_for_admin_routing` (admin-only thereafter). Full transition table and edit side-effects in [`docs/specification/advisory-lifecycle.md §10`](docs/specification/advisory-lifecycle.md).

## Publication pipeline

Entry: `publication.services.publish(advisory, by=user)` — pins the latest `AdvisoryVersion` on a new `PublicationTask` and enqueues `publication.tasks.run_publication` via `transaction.on_commit`. Full pipeline (build OSV/CSAF, validate against vendored schemas, persist `PublicationArtifact`, clone into a fresh tempdir, write, commit, push, atomic finalisation under `select_for_update`, failure handling) in [`docs/specification/architecture.md §4`](docs/specification/architecture.md). Failed exports surface in the Admin Console's Publication page (`/admin/publications/`).

**Auth modes** for the publication repo:
- `PUB_REPO_AUTH=ssh` — a per-call `GIT_SSH` wrapper execs ssh with `IdentitiesOnly=yes`, `BatchMode=yes`, `StrictHostKeyChecking=accept-new` (`GIT_SSH_COMMAND` would need the shell the production image doesn't have). Use a pre-populated known_hosts image in prod for strict checking.
- `PUB_REPO_AUTH=token` — rewrites HTTPS URL with `https://x-access-token:$PUB_REPO_TOKEN@…`; token stripped from every error/audit/artifact/notification surface.

## Frontend / CSP

Server-rendered Django templates + HTMX, one stylesheet (`static/advisoryhub.css`), hand-written vanilla JS. A **nonce-based `script-src 'strict-dynamic'` CSP** (via django-csp; **enforced by default**, set `CSP_REPORT_ONLY=True` to fall back to Report-Only) forbids inline script *and* — via `style-src 'self'` with no `'unsafe-inline'` — inline styles, so when touching templates/JS:

- **No inline `on*=` handlers, no `hx-on::…`, no per-element `hx-headers`.** Add interactive behaviour through the global delegated controllers in `static/advisoryhub-{dialogs,htmx,forms}.js` (open/close native `<dialog>` via `data-dialog-open`/`-close`/`-host`; CSRF is injected on every htmx request from a single `<meta name="csrf-token">` via `htmx:configRequest`). htmx `allowEval`/`allowScriptTags` are off.
- Any genuinely-inline `<script>` (e.g. the pre-paint theme bootstrap) must carry `nonce="{{ request.csp_nonce }}"`.
- **No inline `style="…"` / `<style>`** (`style-src 'self'` blocks them) — put rules in `advisoryhub.css`. htmx's own indicator-`<style>` injection is disabled (`htmx.config.includeIndicatorStyles = false` in `advisoryhub-htmx.js`); the `.htmx-indicator` rules live in the stylesheet instead.
- Reference assets only with `{% static %}` — prod serves **content-hashed** files via WhiteNoise `CompressedManifestStaticFilesStorage`. Inter is **self-hosted** (`static/fonts/`); there is no font CDN.
- Multi-line `{# #}` comments are forbidden (Django renders them literally — `dev/check_template_comments.py` guards this).
- **Browser-support policy:** the frontend targets *Baseline Newly Available* features and adopts them **natively without polyfills** when support is broad across current Chrome/Edge/Firefox/Safari — e.g. CSS `@layer`, `light-dark()`, and the `popover` attribute (the account menu in `base.html` is a native `[popover]` toggled by `popovertarget`, giving click/Escape/light-dismiss with no JS). Prefer a native feature with graceful degradation over a vendored polyfill.

## Configuration

`docker-compose.yml`'s `x-django-env` anchor is the canonical dev configuration (reused by `web` and `worker`); **don't edit env files for dev**. `.env.example` documents every prod knob and is reference-only — it is *not* loaded by docker-compose. `dev/kanidm/.env.kanidm` is the only file compose actually loads at runtime (for the OIDC client secret minted by the bootstrap script).

Notable knobs: `OIDC_GROUP_CLAIM`, `OIDC_ADMIN_GROUP`, `STEP_UP_REQUIRED` (re-auth gate before publish), `CSP_REPORT_ONLY` (CSP is enforced by default; set `True` for Report-Only) + `CSP_REPORT_URI`, `READYZ_INCLUDE_PUB_REPO` / `READYZ_INCLUDE_BROKER` (extra `/readyz` probes), `RATELIMIT_ENABLE`, `PMI_ROSTER_SYNC_ENABLED` (+ `ECLIPSE_API_*` OAuth2 creds — security-team roster sync, off by default), `SIMILARITY_CHECK_ENABLED` (+ `SIMILARITY_LLM_*` provider/model/key/base-url — LLM duplicate detection, off by default; enabling sends advisory content to the configured provider, INV-SIM-2).

## Releases

Tag-driven; full runbook in [`docs/contributing/releasing.md`](docs/contributing/releasing.md). `mise run release -- X.Y.Z` bumps every recorded version in lockstep (`pyproject.toml` + `uv.lock` via `uv version`, `Chart.yaml` `version`/`appVersion`) and creates the signed `chore(release)` commit + signed `vX.Y.Z` tag; pushing the tag triggers `release-image.yml` (container image → ghcr.io, signed, SBOM + provenance) and `release.yml` (version gate → git-cliff notes → wait-for-image → Helm chart → `oci://ghcr.io/<owner>/charts`, cosign-signed → GitHub release with chart/SBOM/checksums attached), and `docs.yml` (versioned documentation → GitHub Pages: `X.Y.Z` + `latest` via mike on the gh-pages branch, `dev` tracks main). `mise run release-check` asserts the version lockstep anytime.

**Workflow conventions** (gated by zizmor — `mise run zizmor`, prek hook, and the `workflow-security.yml` job): every `uses:` is pinned to a full commit SHA with a trailing `# vX.Y.Z` comment that Dependabot maintains — keep both when editing workflows; every job starts with `step-security/harden-runner` (audit); checkouts set `persist-credentials: false`; step outputs are expanded via `env:` indirection, never inline in `run:`. Suppressions live in `.github/zizmor.yml` with rationale.

## Deferred / out of scope

- No public anonymous website (lives in the consumer git repo's CI output).
- No real MITRE CVE integration — `workflows.CveRequestTask` is an internal queue.
- Tests do not require a real OIDC provider, real email, or a real Git remote (Phase D tests use a temporary local bare repo and skip if `git` isn't on PATH).

## Commit policy

When creating commits in this repository, every rule below must be respected:

- Every commit must be signed (`-S`) —preferably with ssh keys in sandboxes — and signed-off (`-s`).
- Every commit message must follow the Conventional Commits specification.
- Never add a `Co-Authored-By` Git trailer to the commit message footer (this intentionally overrides the default Co-Authored-By behaviour).
- Every AI-generated commit MUST include this Git trailer in the commit message footer:

```text
Assisted-by: <AGENT_NAME>:<MODEL_VERSION>
```

Examples:

```text
Assisted-by: Codex:gpt-5.4-mini
Assisted-by: Claude:claude-sonnet-4-6
```
