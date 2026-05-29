# AdvisoryHub

Django application for authoring, reviewing, publishing, and auditing
security advisories for Eclipse Foundation projects. Published advisories
are exported to OSV and CSAF JSON, committed, and pushed to a separate
publication Git repository whose own CI/CD renders the public website.
AdvisoryHub itself is the **private** authoring/review/audit system —
there is no public anonymous surface in this codebase.

Stack: Python 3.14, Django 5.2 LTS, PostgreSQL, Celery + Valkey,
mozilla-django-oidc, server-rendered templates with HTMX.

## Specifications

The authoritative source for what this system *is* and *does* lives in
`docs/specification/`:

- [`invariant.md`](docs/specification/invariant.md) — load-bearing rules
  with stable `INV-*` IDs, severity tiers, and enforcement file paths.
- [`architecture.md`](docs/specification/architecture.md) — tech stack,
  full app layout, architectural patterns, publication & GHSA pipelines,
  env-var inventory, operations, testing strategy.
- [`permissions.md`](docs/specification/permissions.md) — authorization
  model: actors, roles, capability matrix, state-conditioned overrides,
  enforcement surfaces.
- [`advisory-lifecycle.md`](docs/specification/advisory-lifecycle.md) —
  four lifecycle states plus three orthogonal sub-machines (review,
  CVE-request, publication-task) with transition tables and a sequence
  diagram.
- [`requirements.md`](docs/specification/requirements.md) — top-down
  functional spec: actors, domain objects, functional & non-functional
  requirements, use cases.

If you're contributing code, read the relevant spec file before making
non-trivial changes and cite `INV-*` IDs in commits and PRs.

## Running locally

`docker-compose.yml` is **dev-only** — every value it sets is a fixture,
no real secrets, and no `.env` file is required. The one variable that's
genuinely random (the OIDC client secret) is minted by the kanidm
bootstrap script and written to a file compose loads automatically.

First-run flow:

```sh
docker compose up -d kanidm                # start the dev OIDC provider
bash dev/kanidm/setup.sh                   # one-time: cert, users, OAuth2 client
docker compose up                          # web + worker pick up the secret
```

After that, plain `docker compose up` is enough.

Then in another terminal:

```sh
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_demo \
    --with-publish-repo /tmp/advisoryhub-pub.git
```

The app is served at <http://localhost:8000>. Sign in with
`alice@example.org` / `correcthorsebatterystaple` (the demo users seeded
by `dev/kanidm/setup.sh` align 1:1 with what `seed_demo` creates Django-side)
and walk a draft → review → publish flow end-to-end.

To **reset** the dev environment:

```sh
docker compose down -v                     # wipes Postgres + kanidm volumes
docker compose up -d kanidm
bash dev/kanidm/setup.sh
docker compose up
```

## With mise (optional)

If you use [mise](https://mise.jdx.dev), it wraps the flows above so you don't
have to remember the individual commands:

```sh
mise trust && mise run setup     # install uv + prek, sync the locked .venv, wire git hooks
mise run kanidm-up               # start the dev OIDC provider
mise run kanidm-setup            # one-time: cert, users, OAuth2 client
mise run up                      # web + worker (full stack)
mise run migrate && mise run seed
```

`mise tasks` lists them all (`test`, `test-pg`, `lint`, `fix`, `typecheck`, `ty`,
`check`, `reset`, …). mise is a convenience wrapper only: tool versions live in
`uv.lock`, the Python version in `.python-version`, and CI runs these same tasks —
the raw `uv` / `docker compose` commands above stay canonical.

## Configuration

`docker-compose.yml`'s `x-django-env` anchor is the canonical dev
configuration (reused by `web` and `worker`); **don't edit env files for
dev**. For **production**, `.env.example` documents every knob with
secret-vs-config markers — it is a reference for whatever secret manager
or platform manifest your deploy uses (Kubernetes Secrets, Docker Swarm
secrets, AWS SSM, …) and is *not* loaded by docker-compose. The full
env-var inventory with groups, defaults, and descriptions is in
[`architecture.md §7`](docs/specification/architecture.md).

## Running tests

```sh
DJANGO_SETTINGS_MODULE=config.settings.test pytest
```

Default test DB is SQLite (fast); CI also runs Postgres via
`TEST_DATABASE_URL=postgres://…` to exercise the append-only audit
triggers. Testing strategy, conventions, and the dual-database setup are
documented in [`architecture.md §9`](docs/specification/architecture.md).

## Code quality

Lint, format, type, and Django checks run locally through
[prek](https://github.com/j178/prek) — the fast Rust reimplementation of
pre-commit — from [`.pre-commit-config.yaml`](.pre-commit-config.yaml). The
hooks invoke the Python tools out of the project venv, so they run the exact
versions pinned in `uv.lock`: what passes locally is what CI runs.

```sh
mise run setup             # one-shot: installs uv+prek, syncs .venv, wires hooks
# …or by hand:
uv sync --extra dev        # install the pinned ruff / mypy the hooks call
uv tool install prek       # or: pipx install prek / cargo install prek / mise install
prek install               # wire up the pre-commit AND pre-push git hooks
```

Once installed the hooks fire automatically:

- **on commit** — file hygiene (trailing whitespace, end-of-file, merge
  markers, private-key detection, …) plus `ruff check --fix` and `ruff format`.
- **on push** — additionally `mypy` (+ django-stubs), `manage.py
  makemigrations --check`, and `manage.py check`.

Run them on demand any time:

```sh
prek run --all-files                          # commit-stage checks
prek run --all-files --hook-stage pre-push    #   + type & Django checks
prek run --all-files --hook-stage manual      # advisory `ty` type-check
```

## Out of scope

- No public anonymous website — that lives in the consumer publication
  Git repo's CI output.
- No real MITRE CVE integration — `workflows.CveRequestTask` is an
  internal queue.
- Tests do not require a real OIDC provider, real email delivery, or a
  real Git remote (the publication tests use a temporary local bare repo
  and skip if `git` isn't on PATH).
