# AdvisoryHub

AdvisoryHub is a Django application for authoring, reviewing, publishing,
and auditing security advisories for Eclipse Foundation projects. Published
advisories are exported to OSV and CSAF JSON, committed, and pushed to a
separate publication Git repository whose own CI/CD renders the public
website. AdvisoryHub itself is the **private** authoring/review/audit
system — there is no public anonymous surface in the application.

Stack: Python 3.14, Django 5.2 LTS, PostgreSQL, Celery + Valkey,
mozilla-django-oidc, server-rendered templates with HTMX.

## Where to go

- **[User manual](manual/README.md)** — task-oriented guides for the people
  who use AdvisoryHub, one per role: vulnerability reporter,
  collaborator/viewer, project security team, and in-app administrator.
- **[Operations](operations/README.md)** — the operator manual: installing,
  configuring, running, and maintaining the service in production.
- **[Specification](specification/README.md)** — the authoritative
  description of what the system *is* and *does*: invariants (`INV-*` IDs),
  architecture, permissions, the advisory lifecycle, and requirements.
- **[Contributing](contributing/README.md)** — the developer guide: local
  dev environment, tests, code-quality gates, commit conventions, and the
  release runbook.

!!! note "Versioned documentation"
    The version selector in the header switches between documentation
    versions: `latest` is the newest release, numbered versions are
    immutable per-release snapshots, and `dev` tracks the tip of `main`.
