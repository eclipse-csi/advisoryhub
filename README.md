# AdvisoryHub

Django application for authoring, reviewing, publishing, and auditing
security advisories for Eclipse Foundation projects. Published advisories
are exported to OSV and CSAF JSON, committed, and pushed to a separate
publication Git repository whose own CI/CD renders the public website.
AdvisoryHub itself is the **private** authoring/review/audit system —
there is no public anonymous surface in this codebase.

Stack: Python 3.14, Django 5.2 LTS, PostgreSQL, Celery + Valkey,
mozilla-django-oidc, server-rendered templates with HTMX.

The documentation below is also published as a **versioned** site at
<https://mbarbero.github.io/advisoryhub/> — `latest` is the newest release,
numbered versions are per-release snapshots, `dev` tracks `main`.

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

## Manuals

Task-oriented guides for the people who use and run AdvisoryHub:

- [`docs/manual/`](docs/manual/) — **end-user** guides, one per role
  (vulnerability reporter, collaborator/viewer, project security team, and
  in-app administrator).
- [`docs/operations/`](docs/operations/) — **operator** manual for installing,
  configuring, running, and maintaining the service.

## Quick start

`docker-compose.yml` is **dev-only** — every value it sets is a fixture,
no real secrets, and no `.env` file is required. First-run flow:

```sh
docker login dhi.io                        # one-time: app images base on DHI (free Docker account)
docker compose up -d kanidm                # start the dev OIDC provider
bash dev/kanidm/setup.sh                   # one-time: cert, users, OAuth2 client
docker compose up                          # web + worker pick up the secret
```

Then in another terminal:

```sh
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_demo \
    --with-publish-repo /tmp/advisoryhub-pub.git
```

The app is served at <http://localhost:8000>. Sign in with
`alice@example.org` / `correcthorsebatterystaple` and walk a
draft → review → publish flow end-to-end.

Everything else a developer needs — the reset flow, the optional
[mise](https://mise.jdx.dev) task runner, dev vs prod configuration,
running the tests, the code-quality hooks, commit conventions, and the
release runbook — is in the
[contributor guide](docs/contributing/README.md).

## Out of scope

- No public anonymous website — that lives in the consumer publication
  Git repo's CI output.
- No real MITRE CVE integration — `workflows.CveRequestTask` is an
  internal queue.
- Tests do not require a real OIDC provider, real email delivery, or a
  real Git remote (the publication tests use a temporary local bare repo
  and skip if `git` isn't on PATH).
