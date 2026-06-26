# AdvisoryHub Contributor Guide

This guide is for the **developer** — the person who changes AdvisoryHub's
code and docs. It covers the local dev environment, tests, the code-quality
gates, and the commit conventions. Its companions: the
[`../specification/`](../specification/README.md) set (what the system *is* —
authoritative), the [`../operations/`](../operations/README.md) manual (running the
service in production), and [`releasing.md`](./releasing.md) (the maintainer
runbook for cutting a release).

---

## 1. Before you change anything

The specification set in [`../specification/`](../specification/README.md) is the
single source of truth for what this system *is* and *does*. Read the
relevant file before making non-trivial changes, and cite `INV-*` IDs (from
[`invariant.md`](../specification/invariant.md)) in commits and PRs. Every
behavior change must update the affected spec file(s) **in the same
commit/PR** — a code/spec mismatch is a defect in whichever side drifted.
Any deviation from the spec requires explicit maintainer confirmation
*before* implementation.

## 2. Development environment

`docker-compose.yml` is **dev-only** — every value it sets is a fixture,
no real secrets, and no `.env` file is required. The one variable that's
genuinely random (the OIDC client secret) is minted by the kanidm
bootstrap script and written to a file compose loads automatically.

First-run flow:

```sh
docker login dhi.io                        # one-time: app images base on DHI (free Docker account)
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
docker compose build                       # down -v keeps cached images; rebuild after a Dockerfile/uv.lock change
docker compose up -d kanidm
bash dev/kanidm/setup.sh
docker compose up
```

## 3. With mise (optional)

If you use [mise](https://mise.jdx.dev), it wraps the flows above so you don't
have to remember the individual commands:

```sh
mise trust && mise run setup     # install uv + prek, sync the locked .venv, wire git hooks
mise run kanidm-up               # start the dev OIDC provider
mise run kanidm-setup            # one-time: cert, users, OAuth2 client
mise run up                      # web + worker (full stack)
mise run migrate && mise run seed
```

`mise tasks` lists them all (`test`, `lint`, `fix`, `typecheck`, `ty`,
`check`, `build`, `reset`, `docs-build`, `docs-serve`, …). mise is a convenience wrapper only: tool versions live in
`uv.lock`, the Python version in `.python-version`, and CI runs these same tasks —
the raw `uv` / `docker compose` commands above stay canonical.

## 4. Configuration

`docker-compose.yml`'s `x-django-env` anchor is the canonical dev
configuration (reused by `web` and `worker`); **don't edit env files for
dev**. For **production**, `.env.example` documents every knob with
secret-vs-config markers — it is a reference for whatever secret manager
or platform manifest your deploy uses (Kubernetes Secrets, Docker Swarm
secrets, AWS SSM, …) and is *not* loaded by docker-compose. The full
env-var inventory with groups, defaults, and descriptions is in
[`architecture.md §7`](../specification/architecture.md), and the step-by-step
operator guide (install, run, integrate, operate) is in
[`../operations/`](../operations/README.md).

## 5. Running tests

Tests run against PostgreSQL (the same engine as prod), so start it first:

```sh
docker compose up -d postgres    # or `mise run up` for the full dev stack
DJANGO_SETTINGS_MODULE=config.settings.test pytest
```

`config.settings.test` defaults to the local compose Postgres; set
`TEST_DATABASE_URL` to target a different host/port. `--reuse-db` (in
`addopts`) keeps the test database between runs — pass `--create-db` after a
migration change. Tests do not require a real OIDC provider, real email
delivery, or a real Git remote (the publication tests use a temporary local
bare repo and skip if `git` isn't on PATH). Testing strategy and conventions
are documented in [`architecture.md §9`](../specification/architecture.md).

## 6. Code quality

Lint, format, type, and Django checks run locally through
[prek](https://github.com/j178/prek) — the fast Rust reimplementation of
pre-commit — from [`.pre-commit-config.yaml`](https://github.com/mbarbero/advisoryhub/blob/main/.pre-commit-config.yaml). The
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
  makemigrations --check`, `manage.py check`, and a `pip-audit`
  dependency audit (mirrors CI's security job; needs network).

Run them on demand any time:

```sh
prek run --all-files                          # commit-stage checks
prek run --all-files --hook-stage pre-push    #   + type, Django & dependency-audit checks
prek run --all-files --hook-stage manual      # advisory `ty` type-check
```

### Vendored assets & their updates

Upstream-verbatim files committed into the repo — htmx (`static/htmx.min.js`), the
Inter fonts, the ALTCHA widget (`static/altcha/`), the neoteroi docs CSS, and the
OSV/CSAF/CVE/CVSS JSON schemas (`publication/schemas/`) — are each pinned in a
`*.VERSION` (or `SCHEMAS.VERSION`) file recording the upstream version + SHA-256.
`mise run verify-vendor` (a commit-stage hook + CI) fails if a committed file drifts
from its pinned hash.

Updates are automated by a **scoped, self-hosted Renovate** workflow
(`.github/workflows/renovate.yml`) that tracks only those `.VERSION` files —
Dependabot still owns Python/Actions/Docker, so the two never collide. On a new
upstream release Renovate bumps the version and runs `dev/update_vendored_assets.py`
(`mise run update-vendor`) to re-download, rehash, and re-apply the OSV `ECL-` patch,
then opens a PR.

**Auto-merge policy:** the JSON schemas are payload-validated by the publication test
suite (plus the OSV ecosystem drift guard), so a breaking change fails CI — their PRs
**auto-merge on green**. The frontend assets (htmx / ALTCHA / Inter / neoteroi) have
no behavioral tests, so their PRs are **review-only — do a quick manual smoke** (the
ALTCHA widget on `/report/`, an HTMX action, the OAD-rendered API docs page) before
merging. Re-vendor by hand any time with `mise run update-vendor`.

## 7. Commits & pull requests

- Every commit message follows the
  [Conventional Commits](https://www.conventionalcommits.org/) specification.
- Every commit is signed (`-S`) and signed-off (`-s`).
- Cite the `INV-*` IDs your change touches in the commit message and PR
  description, and update the affected spec file(s) in the same commit/PR
  (see [§1](#1-before-you-change-anything)).
- AI-assisted commits carry an `Assisted-by: <agent>:<model>` trailer in the
  footer — e.g. `Assisted-by: Claude:claude-sonnet-4-6` — and never a
  `Co-Authored-By` trailer.

## 8. Releasing

Releases are tag-driven: one signed `vX.Y.Z` tag produces the container
image, the Helm chart, the GitHub release, and the versioned documentation
site automatically. The maintainer runbook — version lockstep, cutting and
verifying a release, failure recovery — is [`releasing.md`](./releasing.md).

## 9. Documentation

Everything under `docs/` is published as a **versioned** site at
<https://mbarbero.github.io/advisoryhub/> (`.github/workflows/docs.yml`):
`latest` is the newest release, numbered versions are immutable per-release
snapshots (deployed on every `vX.Y.Z` tag), and `dev` tracks `main`. The
site is built with MkDocs + mkdocs-material and versioned with
[mike](https://github.com/jimporter/mike) onto the `gh-pages` branch — the
branch is only the version-state store; the workflow deploys its content to
Pages itself (source: GitHub Actions), so nothing goes live on a bare
branch push.

```sh
mise run docs-serve              # live preview at http://127.0.0.1:8001
mise run docs-build              # strict build — the PR and deploy gate
mise run docs-deploy -- dev      # rehearse a mike deploy into a LOCAL gh-pages branch
```

Link rules (enforced by `mkdocs build --strict` on every docs PR):

- Inside `docs/`, link **relative to the current file** and always to the
  `.md` file itself (`../operations/README.md`, not `../operations/`).
- Anything outside `docs/` (source files, charts, repo configs) gets an
  **absolute GitHub URL** — those files aren't part of the site.
