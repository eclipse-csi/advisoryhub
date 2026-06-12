# AdvisoryHub Specification

This specification set is the **single source of truth** for what
AdvisoryHub *is* and *does*. All development must conform to it: read the
relevant file before making non-trivial changes, cite `INV-*` IDs in
commits and PRs, and update the affected spec file(s) **in the same
commit/PR** as any behavior change — a code/spec mismatch is a defect in
whichever side drifted. Any deviation from the spec requires explicit
maintainer confirmation before implementation.

- [`invariant.md`](./invariant.md) — load-bearing rules with stable
  `INV-*` IDs, severity tiers, and enforcement file paths.
- [`architecture.md`](./architecture.md) — tech stack, full app layout,
  architectural patterns, publication & GHSA pipelines, env-var inventory,
  operations, testing strategy.
- [`permissions.md`](./permissions.md) — authorization model: actors,
  roles, capability matrix, state-conditioned overrides, enforcement
  surfaces.
- [`advisory-lifecycle.md`](./advisory-lifecycle.md) — four lifecycle
  states plus three orthogonal sub-machines (review, CVE-request,
  publication-task) with transition tables and a sequence diagram.
- [`requirements.md`](./requirements.md) — top-down functional spec:
  actors, domain objects, functional & non-functional requirements, use
  cases.
