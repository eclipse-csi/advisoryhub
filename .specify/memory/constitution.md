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

### II. Invariants Are Not Worked Around
`docs/specification/invariant.md` is the authoritative catalog of load-bearing rules; this
constitution does not restate them. Code conflicting with an invariant MUST NOT be written; the
conflict MUST be raised so the invariant can be deliberately revisited. Invariant IDs are never
renumbered or reused. Principles III–V below name areas only; the `INV-*` entries hold the rules.

### III. Server-Side Authorization and Auditability
Authorization MUST be enforced server-side, never in templates or from client-submitted data
(`INV-AUTH-*`, `INV-OIDC-*`). Audit-relevant changes MUST go through the audited service layer,
and the audit log MUST remain append-only (`INV-AUDIT-*`, `INV-ACCESS-5`). The exact scope of
audited mutations is defined by those invariants and `permissions.md`.

### IV. Immutable Versioning and Publication Integrity
Advisory versions are append-only and publication artifacts derive from the pinned immutable
version; a failed publication MUST NOT change the advisory's state (`INV-VERSION-*`,
`INV-LIFECYCLE-3`, `INV-WITHDRAW`).

### V. Secrets and Untrusted Input Never Leak
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

## Technical & Security Constraints

- Stack: Python 3.14, Django 5.2 LTS, PostgreSQL, Celery + Valkey, mozilla-django-oidc, HTMX.
- Advisories MUST NOT import `workflows` at module level (`dev/check_import_direction.py`).
- Vendored assets (htmx, Inter, ALTCHA, JSON schemas) are changed only via the scripted
  update flow (`dev/update_vendored_assets.py`), never hand-edited; checksums MUST verify.
- While maintenance mode is on, only global admins may mutate state (`INV-MAINT-1`).
- GitHub Actions workflows MUST pin `uses:` to full SHAs, start with harden-runner, set
  `persist-credentials: false`, and pass step outputs via `env:` (zizmor-gated).
- Production configuration knobs are documented in `.env.example`; dev config lives in the
  `docker-compose.yml` `x-django-env` anchor.

## Development Workflow & Quality Gates

- Commits MUST be signed (`-S`) and signed-off (`-s`), follow Conventional Commits, and MUST NOT
  carry a `Co-Authored-By` trailer. AI-generated commits MUST include
  `Assisted-by: <AGENT_NAME>:<MODEL_VERSION>` in the footer.
- Before merge, the CI gates MUST pass: lint and format (`ruff`), `mypy`, Django checks and
  `makemigrations --check`, the template-comment and import-direction guards, vendored-asset
  verification, and the full pytest suite. The prek hooks run a local subset of these; CI is
  authoritative.
- Changes planned with Spec Kit follow: specify → (red team gate) → plan → tasks → implement,
  with optional security and staff reviews after plan, tasks, and implement. Small fixes and
  documentation-only or refactoring changes may skip Spec Kit but remain bound by Principle I's
  PR-level obligations.
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
