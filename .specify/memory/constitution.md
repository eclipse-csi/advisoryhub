# AdvisoryHub Constitution

## Core Principles

### I. Specification Is the Source of Truth
The set in `docs/specification/` (`invariant.md`, `architecture.md`, `permissions.md`,
`advisory-lifecycle.md`, `requirements.md`, `openapi.yaml`) defines what the system is and does.
All work MUST conform to it. A code/spec mismatch is a defect. Any deviation from the spec MUST
receive explicit maintainer confirmation before implementation. Commits and PRs MUST cite the
relevant `INV-*` IDs; code comments SHOULD cite them where they explain an enforcement point.

For changes planned with Spec Kit, `spec.md` describes the proposed change and links to the
relevant sections of `docs/specification/`. `plan.md` identifies the affected sections and
applicable `INV-*` rules. `tasks.md` includes any required updates to those sections. Every PR
that changes behavior MUST update the affected canonical specification alongside the code and
tests, whatever the workflow. Reviewers MUST verify that the implementation and the canonical
specification agree. Rationale: the spec is verified against the code; silent drift breaks the
security and publication contracts.

### II. Invariants Are Not Worked Around (NON-NEGOTIABLE)
`docs/specification/invariant.md` is the authoritative catalog of load-bearing rules; this
constitution does not restate them. Code conflicting with an invariant MUST NOT be written; the
conflict MUST be raised so the invariant can be deliberately revisited. Invariant IDs are never
renumbered or reused. Principles III–V below name areas only; the `INV-*` entries hold the rules.

### III. Server-Side Authorization and Auditability (NON-NEGOTIABLE)
Authorization MUST be enforced server-side, never in templates or from client-submitted data
(`INV-AUTH-*`, `INV-OIDC-*`). Audit-relevant changes MUST go through the audited service layer,
and the audit log MUST remain append-only (`INV-AUDIT-*`, `INV-ACCESS-5`). The exact scope of
audited mutations is defined by those invariants and `permissions.md`.

### IV. Immutable Versioning and Publication Integrity (NON-NEGOTIABLE)
Advisory versions are append-only and publication artifacts derive from the pinned immutable
version; a failed publication MUST NOT change the advisory's state (`INV-VERSION-*`,
`INV-LIFECYCLE-3`, `INV-WITHDRAW`).

### V. Secrets and Untrusted Input Never Leak (NON-NEGOTIABLE)
User- or CI-supplied strings MUST be redacted before reaching logs, audit metadata, task errors,
artifacts, or notifications (`INV-AUDIT-2`, `INV-SECRET-*`). Public intake is untrusted
(`INV-INTAKE-*`). LLM-assisted features stay dormant unless explicitly enabled (`INV-SIM-2`).

### VI. Test-Backed Changes Against PostgreSQL
Every behavior change MUST ship with tests that fail without it. Tests run against PostgreSQL
(the production engine), so append-only triggers and JSONB queries are exercised; SQLite is not
acceptable. Tests MUST NOT require a real OIDC provider, email, or remote Git. Migrations MUST be
consistent (`makemigrations --check` clean). Rationale: Postgres-specific guarantees are part of
the security model.

### VII. Strict-CSP, Server-Rendered Simplicity
The frontend is server-rendered Django templates plus HTMX with one stylesheet and vanilla JS. It
MUST comply with the enforced nonce-based CSP: no inline `on*=` handlers, no `hx-on`, no inline
`style`/`<style>`, nonces on any inline script, assets via `{% static %}`, multi-line `{# #}`
comments forbidden. Prefer native Baseline browser features over polyfills. Complexity beyond
this stack (new frameworks, build steps, new services) MUST be justified in the plan.

### VIII. Red Team Qualifying Specs Before Plan
A functional spec matching one or more red team Trigger Criteria (money path, regulatory path,
AI/LLM, immutability/audit, multi-party approval, contracts) MUST have a valid red team findings
report on record, with every finding dispositioned, before `/speckit-plan` proceeds. The
`speckit-red-team-gate` check enforces this. A BLOCKED gate MAY be waived only by a documented,
maintainer-approved waiver recorded in `plan.md` with its justification (e.g. a false positive);
it MUST NOT be skipped silently.

### IX. Security Review of Security-Sensitive Changes
A change planned with Spec Kit that touches an area governed by a Critical-tier invariant in
`docs/specification/invariant.md` (e.g. authorization, OIDC, audit, secrets, intake, publication,
versioning, LLM similarity) MUST run `/speckit-security-review-plan` after `/speckit-plan` and
`/speckit-security-review-branch` after `/speckit-implement`. Every finding MUST be fixed or
dispositioned in the PR; accepting a risk requires maintainer approval recorded with its
justification. Reviews MUST evaluate changes against `invariant.md` and `permissions.md`, which
hold the project's security rules: no separate `security_constitution.md` is maintained, and
`/speckit-security-review-init` MUST NOT create one.

## Technical & Security Constraints

- Stack: Python 3.14, Django 5.2 LTS, PostgreSQL, Celery + Valkey, mozilla-django-oidc, HTMX.
- Advisories MUST NOT import `workflows` at module level (`dev/check_import_direction.py`).
- Vendored assets (htmx, Inter, ALTCHA, JSON schemas) are changed only via the scripted
  update flow (`dev/update_vendored_assets.py`), never hand-edited; checksums MUST verify.
- While maintenance mode is on, only global admins may mutate state (`INV-MAINT-1`).
- GitHub Actions workflows MUST pin `uses:` to full SHAs, start with harden-runner, set
  `persist-credentials: false`, and pass step outputs via `env:` (zizmor-gated).
- Configuration is environment-driven; `config/settings/base.py` is the schema. A new or changed
  knob MUST be reflected in the same PR on every surface that exposes it: `.env.example`
  (production reference), the Helm chart, `docs/operations/configuration.md`, and the dev
  `docker-compose.yml` `x-django-env` anchor when dev needs it. In the chart, non-secret knobs go
  through `values.yaml`, `values.schema.json` and the `advisoryhub.envMap` ConfigMap mapping;
  secret material is added only as an expected key of the env Secret (documented in the chart
  README), never to the ConfigMap.

## Development Workflow & Quality Gates

- Commits MUST be signed (`-S`) and signed-off (`-s`), follow Conventional Commits, and MUST NOT
  carry a `Co-Authored-By` trailer. AI-generated commits MUST include
  `Assisted-by: <AGENT_NAME>:<MODEL_VERSION>` in the footer.
- Before merge, the CI gates MUST pass: lint and format (`ruff`), `mypy`, Django checks and
  `makemigrations --check`, the template-comment and import-direction guards, vendored-asset
  verification, the Helm chart checks (`helm-lint`, `helm-validate`), and the full pytest suite.
  The prek hooks run a local subset of these; CI is authoritative.
- Changes planned with Spec Kit follow: specify → (red team gate) → plan → tasks → implement.
  The security reviews after plan and implement are mandatory for changes covered by
  Principle IX and optional otherwise; the task-level security review and the staff review
  after implement are optional. Small fixes and documentation-only or refactoring changes may
  skip Spec Kit but remain bound by Principle I's PR-level obligations.
- Releases are tag-driven via `mise run release`, keeping all recorded versions in lockstep.

## Governance

This constitution supersedes other practices for this repository; it complements
`docs/specification/`, which remains authoritative for system behavior. Amendments require a PR
documenting the change and rationale, maintainer approval, and updates to any dependent artifacts
in the same PR. Versioning follows semantic versioning: MAJOR for backward-incompatible principle
removal or redefinition, MINOR for a new principle/section or materially expanded guidance, PATCH
for clarifications. Every PR and review MUST verify compliance with this constitution; any
complexity or deviation MUST be justified in writing. Runtime development guidance lives in
`CLAUDE.md` and `CONTRIBUTING.md`.

**Version**: 1.0.0 | **Ratified**: 2026-11-19 | **Last Amended**: 2026-11-19
