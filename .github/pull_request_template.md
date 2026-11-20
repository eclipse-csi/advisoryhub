<!--
Thank you for contributing to AdvisoryHub!

This repository is public. Never put embargoed vulnerability details, real advisory
content, reporter identities, tokens or other secrets in a pull request. A fix for an
undisclosed vulnerability in AdvisoryHub itself is coordinated privately first, not
described in a public pull request.

The title is a Conventional Commit (e.g. `fix(publication): …`, `feat(advisories)!: …`):
it becomes the squash commit that git-cliff turns into the release notes.

Fill in the sections below. Remove any section that does not apply, but keep the
"Specification & invariants" and "Tests" sections.
-->

## Description

<!-- What does this PR do, and why? Start with the effect on users (reporter, security
team, collaborator / viewer, global admin) or operators, then the internals. -->

### Related issue

<!-- Link the issue this PR addresses, e.g. "Fixes #123" or "Relates to #123". -->

Fixes #

### Type of change

<!-- Check all that apply. -->

- [ ] 🐛 Bug fix (non-breaking change fixing an issue)
- [ ] ✨ New feature (non-breaking change adding functionality)
- [ ] 💥 Breaking change (users, operators or consumers must act, or get a different result without changing anything)
- [ ] 🔒 Security hardening (closes a gap without changing legitimate use)
- [ ] 📝 Documentation only
- [ ] 🔧 Refactoring / internal change (no functional change)
- [ ] 📦 Build, CI, Helm chart or dependencies

### Breaking change details

<!-- What breaks, who is affected (a role, deployments and operators, Helm chart users,
API / GHSA webhook clients, the publication repository and its website), and the
migration path (configuration, chart values, migrations, data, deploy order).
Remove this section otherwise. -->

## Specification & invariants

<!-- docs/specification/ is the source of truth (constitution, Principle I): a behavior
change updates the affected specification files in this PR. -->

- Invariants concerned: <!-- e.g. INV-AUTH-1, INV-AUDIT-2 — or "none" -->
- Spec Kit feature: <!-- specs/<NNN-feature>/ — remove the line if not planned with Spec Kit -->
- [ ] Specification updated in this PR: <!-- files and sections -->
- [ ] No behavior change: specification unaffected
- [ ] Changes behavior the specification defined, confirmed by a maintainer before implementation: <!-- link -->

## Security review

<!-- Required (constitution, Principle IX) for a change planned with Spec Kit that touches
an area governed by a Critical-tier invariant: authorization, OIDC, audit, secrets,
intake, publication, versioning, LLM similarity. Every finding is fixed or dispositioned
here; an accepted risk needs maintainer approval and its justification.
Remove this section for a change outside these areas. -->

- [ ] Security review of this diff: <!-- command, commit covered, verdict -->
  - Findings and disposition: <!-- fixed in <commit> / accepted by <maintainer>: <justification> -->
- [ ] Red team findings report (Principle VIII): <!-- specs/<NNN-feature>/red-team-findings-*.md -->

## Tests

<!--
Every behavior change ships with tests that fail without it (Principle VI). Tests run
against PostgreSQL and need no real OIDC provider, e-mail or remote Git.
-->

- [ ] Tests added / updated: <!-- files -->
- [ ] No test added: <!-- why, e.g. documentation only -->

Checks run on this diff: <!-- e.g. `mise run test`, `mise run lint`, `mise run typecheck`, `mise run check`, `mise run docs-build`, `mise run helm-validate` — and the ones skipped, with the reason -->

### Manual testing

<!-- Check what was actually exercised and fill in the details. -->

- [ ] Dev stack (`docker compose` + Kanidm + `seed_demo`):
  - Demo users / roles: <!-- e.g. admin@example.org (global admin), alice@example.org (security team), carol@example.org (no access) -->
  - Flows exercised: <!-- e.g. public report → triage → promote; draft → review → publish to the local bare repo; Admin Console page … -->
- [ ] Helm chart installed or upgraded on a cluster: <!-- cluster, values, upgraded from version … -->
- [ ] Not tested manually

### How to reproduce / test scenario

<!-- Step by step, so a reviewer can reproduce your testing, e.g.:
1. `mise run reset && mise run migrate && mise run seed`
2. Sign in as alice@example.org and open the advisory …
3. …
-->

### Screenshots

<!-- Required for changes to templates, static CSS / JS or e-mail notifications. Use
seed_demo data only; show the light and dark themes when the styling changes.
Remove otherwise. -->

## Checklist

- [ ] Documentation updated (`docs/manual/`, `docs/operations/`, `docs/contributing/`) and `mise run docs-build` passes
- [ ] API contract (`docs/specification/openapi.yaml`) updated if `/api/`, the GHSA webhook, the intake project picker or a health probe changed
- [ ] Configuration knob added or changed: `.env.example`, Helm chart (`values.yaml`, `values.schema.json`, `advisoryhub.envMap`), `docs/operations/configuration.md`, dev `docker-compose.yml`
- [ ] Migrations included, `makemigrations --check` clean, backward-compatible one release back
- [ ] Templates and JS comply with the strict CSP (no inline script, inline style or `on*=` handler)
- [ ] Commits follow Conventional Commits, are signed (`-S`) and signed-off (`-s`); AI-assisted ones carry `Assisted-by:`

## Notes for reviewers

<!-- Points of attention: risky areas, design decisions, deviations from a principle that
admits one (with the maintainer approval), behavior that depends on configuration
(feature flags, PUB_REPO_AUTH, STEP_UP_REQUIRED, OIDC provider), what was not tested,
suggested review order. -->
