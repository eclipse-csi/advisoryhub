# Application Invariant

This document is the authoritative catalog of **load-bearing rules** the AdvisoryHub
application depends on. An "invariant" here is a property that must hold at all times;
if it is violated, the security model, audit trail, data integrity, or external
publication contract breaks.

If you are about to write code that conflicts with an invariant, **do not work around it**
— stop and raise the conflict so the invariant can be revisited deliberately.

---

## How to use this document

**Stable IDs.** Each invariant has an ID of the form `INV-<CATEGORY>-<N>` (e.g.
`INV-AUTH-3`). IDs never change and are never reused, even after deprecation, so that
PR descriptions, commit messages, and code comments can cite them.

**Severity.** Each invariant carries one of three tiers in its heading:

| Tier         | Meaning |
|--------------|---------|
| **Critical** | Violation breaks the security model or causes silent data corruption (audit tampering, owner escalation, unredacted secrets, drift between AdvisoryHub state and the publication repo). Treat as a release-blocker. |
| **High**     | Violation creates real authorization or integrity bugs but does not directly compromise the audit/security model (e.g. missing in-flight publication lock, review status not reset on edit). |
| **Medium**   | Correctness or hygiene rule; violation produces wrong behaviour but is recoverable (e.g. expiry checks, optional metadata validation). |

**Fields on each invariant.**

- **Statement** — one sentence stating the rule.
- **Rationale** — why the rule exists.
- **Enforced in** — file paths and symbol names where the rule is enforced. No line
  numbers, so the document does not rot when code moves.
- **Violation impact** — what concretely breaks if the rule is violated.
- **Tests** — pointer(s) to the test file(s) that exercise the rule. Best-effort; if a
  test is missing the entry reads `_(test pending)_`.
- **Related** — links to related invariants by ID.

**Adding, changing, deprecating.** See [Appendix A](#appendix-a--adding-a-new-invariant)
and [Appendix B](#appendix-b--deprecating-an-invariant).

---

## Index

| ID | Statement | Category | Severity |
|----|-----------|----------|----------|
| [INV-LIFECYCLE-1](#inv-lifecycle-1) | An advisory has exactly four lifecycle states: `triage`, `draft`, `published`, `dismissed`. | Lifecycle | Critical |
| [INV-VERSION-1](#inv-version-1) | Every advisory has ≥1 `AdvisoryVersion`; content edits append v(n+1); state-only flips do not. | Versions | High |
| [INV-VERSION-2](#inv-version-2) | Workflow tasks pin a specific `AdvisoryVersion` and `PROTECT`-FK against deletion. | Versions | High |
| [INV-LIFECYCLE-2](#inv-lifecycle-2) | `state=triage` is created only by the public intake endpoint. | Lifecycle | Critical |
| [INV-LIFECYCLE-3](#inv-lifecycle-3) | `state` flips to `published` only after a successful Git push. | Lifecycle | Critical |
| [INV-LIFECYCLE-4](#inv-lifecycle-4) | `dismissed` is reversible by owner or admin via `reopen_advisory`. | Lifecycle | High |
| [INV-LIFECYCLE-5](#inv-lifecycle-5) | Triage→draft promotion preserves advisory identity (same row). | Lifecycle | High |
| [INV-REVIEW-1](#inv-review-1) | `review_status` is orthogonal to `state` — never a fifth lifecycle state. | Review | High |
| [INV-REVIEW-2](#inv-review-2) | Review submission freezes content via an immutable snapshot. | Review | High |
| [INV-REVIEW-3](#inv-review-3) | Admins cannot submit for review (only publish). | Review | High |
| [INV-REVIEW-4](#inv-review-4) | Editing a draft resets review status and re-flags republish. | Review | High |
| [INV-AUTH-1](#inv-auth-1) | Authorization is server-side; templates only display. | Authorization | Critical |
| [INV-AUTH-2](#inv-auth-2) | There are exactly three roles: owner, collaborator, viewer. | Authorization | Critical |
| [INV-AUTH-3](#inv-auth-3) | Owner is derived, never assigned. | Authorization | Critical |
| [INV-AUTH-4](#inv-auth-4) | Multi-grant permission resolution takes the maximum rank. | Authorization | High |
| [INV-AUTH-5](#inv-auth-5) | Triage advisories are owner-only for edit / publish / CVE / comment. | Authorization | Critical |
| [INV-AUTH-6](#inv-auth-6) | Admin-routing-flagged advisories are editable only by global admins. | Authorization | High |
| [INV-AUTH-7](#inv-auth-7) | Publication state grants no implicit read access inside AdvisoryHub. | Authorization | Critical |
| [INV-MAINT-1](#inv-maint-1) | While maintenance mode is on, only global admins may mutate state; everyone else is paused server-side. | Maintenance | Critical |
| [INV-AUDIT-1](#inv-audit-1) | The audit log is append-only at both the application layer and the database. | Audit | Critical |
| [INV-AUDIT-2](#inv-audit-2) | All user/CI-supplied strings are redacted before reaching audit / errors / notifications. | Audit | Critical |
| [INV-AUDIT-3](#inv-audit-3) | Every governance action is recorded in the audit log. | Audit | High |
| [INV-AUDIT-4](#inv-audit-4) | Web-originated audit entries include IP and User-Agent. | Audit | Medium |
| [INV-AUDIT-5](#inv-audit-5) | Access-log events are retention-bounded (partitioned, droppable) and disjoint from the timeline. | Audit | Medium |
| [INV-VERSION-3](#inv-version-3) | OSV / CSAF are generated from an immutable `AdvisoryVersion`, never from live data. | Versions | Critical |
| [INV-SECRET-1](#inv-secret-1) | Tokens never appear in `PublicationTask.last_error` or audit metadata. | Secrets | Critical |
| [INV-SECRET-2](#inv-secret-2) | SSH keys and token-bearing URLs are never persisted or logged. | Secrets | Critical |
| [INV-SECRET-3](#inv-secret-3) | Notification bodies are redacted. | Secrets | High |
| [INV-INTAKE-1](#inv-intake-1) | Honeypot trips create `HoneypotSubmission`, never an `Advisory`. | Intake | Critical |
| [INV-INTAKE-2](#inv-intake-2) | The public form has no reporter-email field; anonymous reports cannot be re-associated. | Intake | Critical |
| [INV-INTAKE-3](#inv-intake-3) | Authenticated reporters auto-receive a *viewer* grant on their own report. | Intake | High |
| [INV-INTAKE-4](#inv-intake-4) | Reports filed against the `unsorted` project default to `needs_admin_routing=True`. | Intake | High |
| [INV-OIDC-1](#inv-oidc-1) | Groups are re-synced from OIDC claims on every login; client group data is never trusted. | Identity | Critical |
| [INV-OIDC-2](#inv-oidc-2) | Authorization always reads from the DB groups mirror, never from request input. | Identity | Critical |
| [INV-OIDC-3](#inv-oidc-3) | `is_staff` / `is_superuser` track admin-group membership on each login. | Identity | High |
| [INV-OIDC-4](#inv-oidc-4) | OIDC group claim values are filtered to SPN form before mirroring. | Identity | Medium |
| [INV-OIDC-5](#inv-oidc-5) | Provisioned (shadow) roster users hold no authorization; roster sync never writes `user.groups`. | Identity | High |
| [INV-ROSTER-1](#inv-roster-1) | Shadow roster members get the team's default notifications for their project only, never internal comments; reach is not access. | Notifications | Medium |
| [INV-PUB-1](#inv-pub-1) | Each publication clone uses a fresh `TemporaryDirectory`. | Publication | Critical |
| [INV-PUB-2](#inv-pub-2) | SSH and token authentication are mutually exclusive. | Publication | Medium |
| [INV-PUB-3](#inv-pub-3) | Publication clones are shallow (`depth=1`). | Publication | Medium |
| [INV-PUB-4](#inv-pub-4) | The `state` flip and `PublicationTask` outcome share one transaction. | Publication | Critical |
| [INV-PUB-5](#inv-pub-5) | The Celery task is enqueued via `transaction.on_commit`. | Publication | High |
| [INV-PUB-6](#inv-pub-6) | OSV and CSAF documents are validated against vendored schemas before push. | Publication | High |
| [INV-PERM-1](#inv-perm-1) | Mature-publisher projects may publish without a top-level review. | Permissions | High |
| [INV-PERM-2](#inv-perm-2) | Mature-publisher status lives on `Project`, not on a group or env var. | Permissions | High |
| [INV-PERM-3](#inv-perm-3) | No one can publish while `review_status=submitted`. | Permissions | High |
| [INV-ACCESS-1](#inv-access-1) | Grants are unique per `(advisory, principal)`. | Access | High |
| [INV-ACCESS-2](#inv-access-2) | Invitations match recipient email case-insensitively. | Access | High |
| [INV-ACCESS-3](#inv-access-3) | Invitations expire (default 14 days). | Access | Medium |
| [INV-ACCESS-4](#inv-access-4) | The grant API rejects `permission="owner"`. | Access | Critical |
| [INV-ACCESS-5](#inv-access-5) | Grant create/update/revoke is audited. | Access | High |
| [INV-COMMENT-1](#inv-comment-1) | `is_internal` is fixed at creation. | Comments | High |
| [INV-COMMENT-2](#inv-comment-2) | Internal-comment visibility is re-checked at read time. | Comments | High |
| [INV-COMMENT-3](#inv-comment-3) | Comment edits append immutable `CommentVersion` rows. | Comments | Medium |
| [INV-COMMENT-4](#inv-comment-4) | Comment redaction is irreversible. | Comments | Medium |
| [INV-CONCURRENCY-1](#inv-concurrency-1) | A second publish attempt while one is in flight raises `PublicationInProgress`. | Concurrency | High |
| [INV-CONCURRENCY-2](#inv-concurrency-2) | Snapshot creation and state flips are wrapped in `transaction.atomic`. | Concurrency | Critical |
| [INV-CVE-1](#inv-cve-1) | At most one open CVE request per advisory. | CVE | High |
| [INV-CVE-2](#inv-cve-2) | `assigned_cve_id` is effectively write-once. | CVE | High |
| [INV-CVE-3](#inv-cve-3) | The CVE-request ban is admin-only. | CVE | Medium |
| [INV-ID-1](#inv-id-1) | Advisory IDs match the canonical `ECL-…` regex and are immutable. | Identifiers | High |
| [INV-ID-2](#inv-id-2) | `ghsa_id` is unique when non-empty. | Identifiers | High |
| [INV-ID-3](#inv-id-3) | `assigned_cve_id` is validated against `CVE-YYYY-NNNN…`. | Identifiers | Medium |
| [INV-PROJECT-1](#inv-project-1) | A project's security team is a Django `Group`. | Projects | Medium |
| [INV-PROJECT-2](#inv-project-2) | The `unsorted` sentinel project owns all unrouted triage. | Projects | High |
| [INV-IMPL-1](#inv-impl-1) | `Advisory.delete()` is blocked at the model layer (and DB trigger). | Structural | Critical |
| [INV-IMPL-2](#inv-impl-2) | `AuditLogEntry.delete()` is blocked. | Structural | Critical |
| [INV-IMPL-3](#inv-impl-3) | `CommentVersion` rows are append-only. | Structural | High |
| [INV-IMPL-4](#inv-impl-4) | Advisory ID generation retries on collision (bounded). | Structural | Medium |
| [INV-IMPL-5](#inv-impl-5) | `AdvisoryVersion` rows are append-only. | Structural | Critical |
| [INV-PRIVACY-1](#inv-privacy-1) | Advisories without access are not enumerable. | Privacy | High |
| [INV-PRIVACY-2](#inv-privacy-2) | Notification recipients are re-checked at send time. | Privacy | High |
| [INV-PRIVACY-3](#inv-privacy-3) | `reporter_display_name` is display-only; never used for authorization. | Privacy | Medium |

---

## 1. Lifecycle & state machines

<a id="inv-lifecycle-1"></a>
### INV-LIFECYCLE-1 — Four lifecycle states only   [Critical]

**Statement.** An advisory is in exactly one of `triage`, `draft`, `published`, or
`dismissed`. The review workflow is *not* a fifth lifecycle state; it lives on the
separate `review_status`, with the reviewed content pinned via
`workflows.ReviewTask.version` into the append-only `AdvisoryVersion` log
(see [INV-VERSION-1](#inv-version-1)).

**Rationale.** Keeps the state machine small and unambiguous. Review and CVE workflows
are orthogonal status machines so an advisory does not get stuck in a hybrid state.

**Enforced in.**
- `advisories/models.py` — `Advisory.State` text-choices enum.
- `advisories/permissions.py` — every capability predicate dispatches on `advisory.state`.

**Violation impact.** Adding a fifth state silently bypasses every `advisory.state ==
State.DRAFT` check, breaking edit / publish / dismiss guards.

**Tests.** `advisories/tests/test_models.py`, `advisories/tests/test_permissions.py`.

**Related.** [INV-REVIEW-1](#inv-review-1), [INV-LIFECYCLE-2](#inv-lifecycle-2),
[INV-VERSION-1](#inv-version-1).

---

<a id="inv-lifecycle-2"></a>
### INV-LIFECYCLE-2 — Triage is created only by public intake   [Critical]

**Statement.** Rows with `state=triage` are created exclusively via
`advisories.services.submit_triage_report` (the public intake handler). No API,
admin, or internal flow creates `state=triage` directly.

**Rationale.** Triage is the dedicated bucket for *untrusted* anonymous submissions;
data that arrives through authenticated paths must not borrow that label and the
relaxed authorization that goes with it.

**Enforced in.**
- `advisories/services.py` — `submit_triage_report` is the only constructor.
- `intake/views.py` — the public `POST /report/` form is its only caller path.

**Violation impact.** Creating a `state=triage` row outside intake skips honeypot
checks, intake metadata, and the auto-grant logic in [INV-INTAKE-3](#inv-intake-3).

**Tests.** `intake/tests/test_views_public.py`, `advisories/tests/test_triage.py`.

**Related.** [INV-INTAKE-1](#inv-intake-1), [INV-INTAKE-2](#inv-intake-2), [INV-INTAKE-3](#inv-intake-3).

---

<a id="inv-lifecycle-3"></a>
### INV-LIFECYCLE-3 — `state` flips to `published` only after Git push   [Critical]

**Statement.** `Advisory.state` becomes `published` only inside the publication task,
inside a `select_for_update` block, **after** `publication.git_service.publish_files`
returns successfully. Any failure (validation, clone, write, commit, push) leaves the
advisory in its prior state and marks the `PublicationTask` failed.

**Rationale.** The publication Git repository is the source of truth for what is
public. Flipping `state=published` before the push could leave AdvisoryHub claiming
a row is public while no commit exists in the consumer repo.

**Enforced in.**
- `publication/tasks.py` — `run_publication` flips state only on the success branch.
- `publication/services.py` — `mark_failed` keeps prior state and stamps `last_error`.
- `publication/git_service.py` — `publish_files` returns only after `git push`.

**Violation impact.** Drift between AdvisoryHub and the publication repo. Republish
button stops being idempotent because the prior commit may never have happened.

**Tests.** `publication/tests/test_pipeline.py`, `publication/tests/test_git_service.py`.

**Related.** [INV-PUB-4](#inv-pub-4), [INV-VERSION-3](#inv-version-3).

---

<a id="inv-lifecycle-4"></a>
### INV-LIFECYCLE-4 — `dismissed` is reversible by owner/admin   [High]

**Statement.** While `state=dismissed`, an advisory cannot be published, edited, or
take CVE workflow actions. Owners and admins may **reopen** a dismissed advisory
via `advisories.services.reopen_advisory`; reopening returns it to its
pre-dismissal state (`triage` or `draft`, recorded in
`Advisory.dismissed_from_state`). There is no direct `dismissed → published`
transition — re-publishing requires going through the normal publication flow
from the reopened state.

**Rationale.** Dismissals are often the right call (duplicate, not-a-vuln,
out-of-scope) but humans make mistakes and new information surfaces. Reopening
into a non-published working state does not bypass any gate — the review and
publication flows still apply on the way back out. Keeping reopen owner-gated
preserves the audit story: reopen creates an `ADVISORY_REOPENED` row, and the
prior `ADVISORY_DISMISSED` plus `dismissed_reason` stay visible as historical
context.

Dismiss also tears down any pending review state at dismissal time
(`workflows.services.cancel_pending_review` runs from both dismiss paths),
so a reopened advisory always re-enters the pipeline with
`review_status=NONE` and no `OPEN` `ReviewTask`. This closes the
"surviving APPROVED" loophole that would otherwise let an owner publish
on a reopened advisory without a fresh review ([INV-PERM-3]).

**Enforced in.**
- `advisories/permissions.py` — `can_reopen` requires `state=dismissed` and
  owner rank. `can_publish`, `can_submit_for_review`, `can_request_cve`, and
  `can_edit` still reject `state=dismissed` (no in-state editing).
- `advisories/services.py::reopen_advisory` — re-checks permission, locks the
  row, and flips state to `Advisory.dismissed_from_state`. CVE side-effects
  (orphan reattachment, cancelled-request restoration) are orchestrated
  through `workflows.services`; see [INV-CVE-3](#inv-cve-3).
- `advisories/services.py::dismiss_triage` and the draft-dismiss block in
  `advisories/views.py::advisory_dismiss` — call
  `workflows.services.cancel_pending_review` so dismissed advisories
  always carry `review_status=NONE` and no `OPEN` `ReviewTask`.

**Violation impact.** Without `can_reopen` gating, a non-owner could revive
suppressed content. Without re-checking state in `reopen_advisory`, a stale
form could push a non-dismissed advisory into an unexpected target state.

**Tests.**
- `advisories/tests/test_reopen.py` — service, permission, view, and orphan
  dispositions.
- `advisories/tests/test_permissions.py` — `can_publish` / `can_edit` still
  reject dismissed.

**Related.** [INV-LIFECYCLE-1](#inv-lifecycle-1), [INV-AUTH-1](#inv-auth-1).

---

<a id="inv-lifecycle-5"></a>
### INV-LIFECYCLE-5 — Triage→draft promotion preserves identity   [High]

**Statement.** `promote_triage_to_draft` flips an existing triage row to `draft`. It
does not create a new advisory; the primary key, the public advisory ID, and the
`created_at` timestamp do not change.

**Rationale.** Comments, audit entries, intake metadata, and (if the report was made
by an authenticated reporter) the viewer grant all hang off the advisory PK. Copying
to a new row would orphan them.

**Enforced in.**
- `advisories/services.py` — `promote_triage_to_draft` mutates the same row.
- `audit/models.py` — emits `ADVISORY_TRIAGE_PROMOTED`, referencing the same advisory.

**Violation impact.** Loss of triage history, dropped comments, broken audit chain.

**Tests.** `advisories/tests/test_triage.py`.

**Related.** [INV-INTAKE-3](#inv-intake-3).

---

## 2. Review workflow

<a id="inv-review-1"></a>
### INV-REVIEW-1 — `review_status` is orthogonal to `state`   [High]

**Statement.** `Advisory.review_status` (`none`, `submitted`, `changes_requested`,
`approved`) is a separate dimension from the four lifecycle states. An advisory may
be `state=draft, review_status=approved` without that being a distinct state.

**Rationale.** Reviews can iterate multiple times before publication; conflating
review with lifecycle would either deadlock review or duplicate publication state.

**Enforced in.**
- `advisories/models.py` — separate `state` and `review_status` fields.
- `workflows/models.py` — `ReviewTask` has its own state machine.

**Violation impact.** Permission checks that fold review into `state` lose the
ability to publish a previously-approved-but-now-edited advisory.

**Tests.** `workflows/tests.py`.

**Related.** [INV-LIFECYCLE-1](#inv-lifecycle-1), [INV-REVIEW-4](#inv-review-4).

---

<a id="inv-review-2"></a>
### INV-REVIEW-2 — Review submission freezes content   [High]

**Statement.** Submitting an advisory for review opens a `workflows.ReviewTask`
whose `version` FK pins the current latest `AdvisoryVersion`. Reviewers judge
the payload of that immutable version; subsequent edits to the advisory append
new versions (per [INV-VERSION-1](#inv-version-1)) without changing what the
ReviewTask points at.

**Rationale.** Reviewers must judge a stable version. If the advisory could drift
while review is in flight, "approved" loses meaning.

**Enforced in.**
- `workflows/services.py` — `submit_for_review` reads the latest version via
  `advisory_services.latest_version` and creates `ReviewTask(advisory=…, version=…)`.
- `workflows/models.py` — `ReviewTask.version` is `PROTECT`-FK.
- `advisories/models.py` — `AdvisoryVersion.save`/`delete` block updates
  ([INV-IMPL-5](#inv-impl-5)).

**Violation impact.** Approvals would refer to content that no longer matches the
advisory; reviewers and auditors lose the historical record.

**Tests.** `workflows/tests.py`.

**Related.** [INV-VERSION-1](#inv-version-1), [INV-VERSION-2](#inv-version-2),
[INV-IMPL-5](#inv-impl-5).

---

<a id="inv-review-3"></a>
### INV-REVIEW-3 — Admins cannot submit for review   [High]

**Statement.** `can_submit_for_review` returns `False` for global admins. Admins are
the reviewers and publish directly when `is_mature_publisher` does not apply.

**Rationale.** Prevents the trivial conflict of interest of a reviewer submitting
their own work and immediately approving it.

**Enforced in.**
- `advisories/permissions.py` — `can_submit_for_review` checks `is_global_admin`.

**Violation impact.** Self-approval loop; review becomes a rubber stamp.

**Tests.** `advisories/tests/test_permissions.py`.

**Related.** [INV-PERM-3](#inv-perm-3).

---

<a id="inv-review-4"></a>
### INV-REVIEW-4 — Editing a draft invalidates approval   [High]

**Statement.** Editing a draft advisory that holds `review_status=approved` resets
`review_status` and sets `republish_required=True` (when also published).

**Rationale.** An approved review covers a specific content version; substantive
edits invalidate that approval and must be re-reviewed or, for mature publishers,
deliberately re-published.

**Enforced in.**
- `advisories/services.py` — the edit path resets `review_status`.
- `advisories/models.py` — `republish_required` is set when editing a published advisory.

**Violation impact.** Publication of an unreviewed change; CSAF/OSV diverging from
what was approved.

**Tests.** `advisories/tests/test_views.py`, `workflows/tests.py`.

**Related.** [INV-REVIEW-2](#inv-review-2), [INV-PERM-1](#inv-perm-1).

---

## 3. Authorization

<a id="inv-auth-1"></a>
### INV-AUTH-1 — Server-side authorization on every view/API/task   [Critical]

**Statement.** Permission checks happen in views, API handlers, and Celery tasks.
Templates only render — they never decide who may act.

**Rationale.** Hiding a button is not security. Every state-changing endpoint must
re-verify authorization with the same predicates used to render the page.

**Enforced in.**
- `advisories/permissions.py` — single source for predicates (`can_edit`,
  `can_publish`, `can_dismiss`, `can_request_cve`, `can_submit_for_review`,
  `can_triage`, `can_flag_for_admin_routing`, `can_clear_admin_routing_flag`).
- All view modules import from `advisories.permissions`; templates only display.

**Violation impact.** Direct API requests bypass UI guards; privilege escalation by
crafting a POST.

**Tests.** `advisories/tests/test_views.py`, `api/tests/test_advisories.py`,
`api/tests/test_access.py`.

**Related.** [INV-OIDC-2](#inv-oidc-2).

---

<a id="inv-auth-2"></a>
### INV-AUTH-2 — Three roles only   [Critical]

**Statement.** At most one of the three roles applies to a user on an advisory:
`owner`, `collaborator`, `viewer`. Capabilities by role are as documented in
`CLAUDE.md` and `advisories/permissions.py`.

**Rationale.** Permission resolution must be unambiguous; "what can I do here?" is
a function with a single answer.

**Enforced in.**
- `advisories/permissions.py` — `resolved_permission` returns one of these or `None`.
- `access/models.py` — `AdvisoryAccessGrant.Permission` lists only `collaborator`,
  `viewer` (owner is structural — see [INV-AUTH-3](#inv-auth-3)).

**Violation impact.** Capability-table sprawl; ambiguous permission resolution.

**Tests.** `advisories/tests/test_permissions.py`, `access/tests.py`.

**Related.** [INV-AUTH-3](#inv-auth-3), [INV-AUTH-4](#inv-auth-4).

---

<a id="inv-auth-3"></a>
### INV-AUTH-3 — Owner is derived, never assigned   [Critical]

**Statement.** The `owner` role is not stored. It derives from (a) global admin-group
membership, or (b) project security-team membership. No `AdvisoryAccessGrant` row may
carry `permission="owner"`. A pre-provisioned shadow roster user
([INV-OIDC-5](#inv-oidc-5)) is explicitly *not* an owner — its notification reach
([INV-ROSTER-1](#inv-roster-1)) is not an authorization grant.

**Rationale.** Owner is the most privileged role; if it were grantable, any user with
grant rights could escalate themselves or others, defeating the admin/security-team
gating that defines who may publish.

**Enforced in.**
- `access/models.py` — `Permission.choices` omits `owner`.
- `access/services.py` — `_validate_grantable_permission` raises on `owner`.
- `advisories/permissions.py` — `resolved_permission` derives owner from admin /
  security-team membership.

**Violation impact.** Trivial privilege escalation to owner via the grant API.

**Tests.** `access/tests.py`, `advisories/tests/test_permissions.py`.

**Related.** [INV-AUTH-2](#inv-auth-2), [INV-ACCESS-4](#inv-access-4),
[INV-OIDC-2](#inv-oidc-2).

---

<a id="inv-auth-4"></a>
### INV-AUTH-4 — Multi-grant resolution picks the maximum rank   [High]

**Statement.** When a user holds multiple grants (direct + via groups) on the same
advisory, the **highest** rank applies: `viewer < collaborator < owner`.

**Rationale.** Falling back to the minimum (or the most-recent) would let a viewer
grant *demote* a collaborator unintentionally.

**Enforced in.**
- `advisories/permissions.py` — `resolved_permission` computes max over
  direct + group grants.

**Violation impact.** Users silently lose access; debugging "why can't I edit?" is
painful and inconsistent.

**Tests.** `advisories/tests/test_permissions.py`.

**Related.** [INV-AUTH-2](#inv-auth-2).

---

<a id="inv-auth-5"></a>
### INV-AUTH-5 — Triage advisories are owner-only   [Critical]

**Statement.** When `state=triage`, only owners (admins or project security team)
may edit, publish, request a CVE, or comment. Grantees (including the reporter's
auto-grant) get *read* only until the advisory is promoted to draft.

**Rationale.** Triage rows are *untrusted*. Permitting collaborator-level edits on
an unvetted submission would let a hostile reporter rewrite the report after
submission.

**Enforced in.**
- `advisories/permissions.py` — `can_edit`, `can_publish`, `can_request_cve`,
  comment predicates all gate on `state != TRIAGE` for non-owners.
- `advisories/services.py` — `submit_triage_report` auto-grants `viewer`, not
  `collaborator` (see [INV-INTAKE-3](#inv-intake-3)).

**Violation impact.** Untrusted reporters can mutate their own triage rows, possibly
laundering content before promotion.

**Tests.** `advisories/tests/test_triage.py`, `advisories/tests/test_permissions.py`.

**Related.** [INV-INTAKE-3](#inv-intake-3), [INV-AUTH-6](#inv-auth-6).

---

<a id="inv-auth-6"></a>
### INV-AUTH-6 — Admin-routing-flagged advisories are admin-only   [High]

**Statement.** When `AdvisoryIntakeMetadata.needs_admin_routing=True`, only global
admins can edit, triage, or unflag the advisory. Project owners may *flag* a
misrouted advisory but may not unflag it.

**Rationale.** Misrouted reports must reach an admin for re-routing; otherwise a
project team could quietly close a report that should have gone elsewhere.

**Enforced in.**
- `advisories/permissions.py` — `can_edit`, `can_triage`,
  `can_flag_for_admin_routing`, `can_clear_admin_routing_flag`.

**Violation impact.** Mis-routed reports get suppressed by the wrong team.

**Tests.** `advisories/tests/test_triage.py`.

**Related.** [INV-PROJECT-2](#inv-project-2), [INV-INTAKE-4](#inv-intake-4).

---

<a id="inv-auth-7"></a>
### INV-AUTH-7 — Publication grants no implicit read access   [Critical]

**Statement.** Publishing an advisory inside AdvisoryHub does not make it visible to
anyone who is not already an owner or explicit grantee. The public surface lives in
the separate publication Git repo's website, not here.

**Rationale.** AdvisoryHub is the *authoring* system; published rows inside it may
still contain reviewer-only notes, internal comments, and audit history.

**Enforced in.**
- `advisories/permissions.py` — `resolved_permission` ignores `advisory.state`.
- View querysets filter by access, not by publication state.

**Violation impact.** Internal review notes and PII attached to published advisories
leak to unauthenticated users.

**Tests.** `advisories/tests/test_views.py`, `api/tests/test_advisories.py`.

**Related.** [INV-COMMENT-2](#inv-comment-2), [INV-PRIVACY-1](#inv-privacy-1).

---

<a id="inv-maint-1"></a>
### INV-MAINT-1 — Maintenance mode pauses everyone but admins, server-side   [Critical]

**Statement.** When `MaintenanceMode.is_enabled` is true, every request that would
mutate state (any non-`GET`/`HEAD`/`OPTIONS`/`TRACE` method) from a non-admin is
refused with `503` before reaching the view. Members of `settings.OIDC_ADMIN_GROUP`
are exempt and keep working normally. The banner and disabled buttons are
display-only — they never *grant* or *withhold* access.

**Rationale.** A maintenance pause is an authorization decision: it must hold against
a crafted `POST`, an HTMX action, and the JSON API — not just hidden buttons. Hiding
a button is not security (see [INV-AUTH-1](#inv-auth-1)); the middleware is the
authority.

**Enforced in.**
- `common/middleware.py` — `MaintenanceModeMiddleware` blocks unsafe methods for
  non-admins. Exempt prefixes: auth plumbing (`/oidc/`) and probes/assets so anyone
  can still sign in/out and an admin can lift the pause, plus the HMAC-authenticated
  GHSA webhook (`/ghsa/webhook/`) — machine traffic GitHub stops retrying, so it is
  still received (and recorded) rather than dropped. `/django-admin/` is deliberately
  *not* exempt, so a stale `is_staff` session cannot mutate data there while paused.
- `admin_console/models.py` — `MaintenanceMode` singleton (`pk=1`). Enforcement reads
  the authoritative uncached `is_paused()` (coherent across workers); the banner reads
  the cached `current()` snapshot. `advisories.permissions.is_global_admin` is the
  exemption predicate.
- `common/context_processors.py` + `templates/base.html` + `static/advisoryhub-maintenance.js`
  — display only.

**Violation impact.** A paused (or anonymous) user mutates state during maintenance —
files a report, edits, publishes — defeating the pause and risking writes against an
inconsistent backend mid-maintenance.

**Tests.** `admin_console/test_maintenance.py`.

**Related.** [INV-AUTH-1](#inv-auth-1), [INV-OIDC-2](#inv-oidc-2), [INV-AUDIT-3](#inv-audit-3).

---

## 4. Audit trail integrity

<a id="inv-audit-1"></a>
### INV-AUDIT-1 — Append-only at both layers   [Critical]

**Statement.** `AuditLogEntry` rows are insert-only. Updates and deletes are forbidden
in two independent layers:

1. **Application** — `AuditLogEntry.save()` raises if `pk is not None`; `delete()`
   raises unconditionally.
2. **Database (Postgres)** — triggers `audit_log_no_update` and `audit_log_no_delete`
   raise on `UPDATE` or `DELETE`.

**Scope.** This invariant governs the durable ledger (`AuditLogEntry`) only.
High-volume, non-compliance *access-log* events (advisory views, GHSA/PMI
chatter) are routed to the separate, retention-managed `AccessLogEntry` table,
which is deliberately weaker — see [INV-AUDIT-5](#inv-audit-5).

**Rationale.** Tamper resistance. Even a compromised admin or raw `psql` session
cannot rewrite history; both layers must be subverted, and the database trigger
removal would itself appear in `git log`.

**Enforced in.**
- `audit/models.py` — `AuditLogEntry.save` and `.delete`.
- `audit/migrations/0002_append_only_trigger.py` — DB triggers.

**Violation impact.** Loss of forensic and compliance value of the audit log.

**Tests.** `audit/tests.py`, `audit/test_retention.py`.

**Related.** [INV-AUDIT-2](#inv-audit-2), [INV-AUDIT-3](#inv-audit-3),
[INV-IMPL-2](#inv-impl-2).

---

<a id="inv-audit-2"></a>
### INV-AUDIT-2 — Secrets redacted before persistence   [Critical]

**Statement.** Any user/CI-supplied string that may contain credentials is run
through `audit.services.redact_secrets` (and `publication.git_service._redact` for
Git URLs) before being stored in audit metadata, `PublicationArtifact` rows,
`PublicationTask.last_error`, or notification bodies.

**Rationale.** Keeps tokens, SSH key paths, and bearer-URL forms out of every
downstream surface that an operator might inspect or that might be forwarded.

**Enforced in.**
- `audit/services.py` — `redact_secrets`, called by `record` /
  `record_from_request`.
- `publication/git_service.py` — `_redact` rewrites token-bearing URLs.
- `publication/services.py` — `mark_failed` redacts `error` before save.

**Violation impact.** Credential leak to the audit table, admin console, or e-mail.

**Tests.** `audit/test_redact_ghsa_secrets.py`, `publication/tests/test_git_service.py`.

**Related.** [INV-SECRET-1](#inv-secret-1), [INV-SECRET-2](#inv-secret-2),
[INV-SECRET-3](#inv-secret-3).

---

<a id="inv-audit-3"></a>
### INV-AUDIT-3 — Governance actions are logged   [High]

**Statement.** Every governance-relevant action emits exactly one `AuditLogEntry`:
advisory state changes, access grant / revoke / invitation events, comment
create / edit / redact, CVE-request transitions, review decisions, publication
attempts (success and failure), OIDC group sync changes, intake transitions, and
site-wide maintenance toggles.

**Rationale.** Compliance and forensics rely on a complete record. Missing entries
make incident investigation guesswork.

**Enforced in.**
- `audit/models.py` — `Action` enum enumerates every recordable action.
- Each service module emits its corresponding `Action` (advisories, access,
  comments, workflows, publication, intake, accounts).

**Violation impact.** Silent governance changes; "who did this and when?" cannot
be answered.

**Tests.** Per-module tests; `audit/tests.py` covers the audit machinery itself.

**Related.** [INV-AUDIT-1](#inv-audit-1), [INV-AUDIT-4](#inv-audit-4).

---

<a id="inv-audit-4"></a>
### INV-AUDIT-4 — Web-originated entries carry IP & UA   [Medium]

**Statement.** Audit entries created from an `HttpRequest` (via
`audit.services.record_from_request`) capture the requesting IP and User-Agent.

**Rationale.** Helps correlate suspicious actions across sessions and identify
account compromise.

**Enforced in.**
- `audit/services.py` — `record_from_request`.
- `audit/models.py` — `ip_address`, `user_agent` columns.

**Violation impact.** Reduced ability to investigate incidents.

**Tests.** `audit/tests.py`.

**Related.** [INV-AUDIT-3](#inv-audit-3).

---

<a id="inv-audit-5"></a>
### INV-AUDIT-5 — Access log is retention-bounded, not tamper-proof   [Medium]

**Statement.** The actions in `audit.models.EPHEMERAL_ACTIONS` (advisory views
plus GHSA/PMI machine chatter) are written to `AccessLogEntry`, **not** the
durable ledger. This table is:

1. **Monthly range-partitioned** on `created_at`; retention is a `DROP PARTITION`
   of months older than `AUDIT_ACCESS_LOG_RETENTION_DAYS` (default 90), run daily
   by `audit.tasks.maintain_access_log_partitions`.
2. **Application-layer write-once** (`AccessLogEntry.save()` refuses updates) but
   **not** protected by append-only DB triggers — it must stay droppable, so DB
   `DELETE`/`DROP` is permitted (retention, and `forget_user` deletes a forgotten
   user's rows outright rather than scrubbing them).
3. **Disjoint from the advisory-timeline tiers.** `EPHEMERAL_ACTIONS` must never
   intersect `advisories.timeline` tiers A/B/C, or dropping a partition would
   erase events shown on advisory pages.

**Rationale.** View pings and integration chatter dominate audit volume but carry
no long-term compliance value and never appear on a timeline. Isolating them lets
the ledger stay small and fully tamper-proof while this table is pruned cheaply.

**Enforced in.**
- `audit/models.py` — `AccessLogEntry`, `EPHEMERAL_ACTIONS`.
- `audit/services.py` — `record()` routes by action.
- `audit/migrations/0003_accesslogentry.py` — partitioned table DDL.
- `audit/partitions.py`, `audit/tasks.py` — partition lifecycle / retention.

**Violation impact.** Either unbounded growth (retention disabled/broken) or, if
the disjointness is violated, silent loss of timeline-visible history.

**Tests.** `audit/tests.py`, `audit/test_partitions.py`,
`advisories/tests/test_access_log_disjoint.py`, `audit/test_retention.py`.

**Related.** [INV-AUDIT-1](#inv-audit-1), [INV-AUDIT-2](#inv-audit-2),
[INV-AUDIT-4](#inv-audit-4).

---

## 5. Version history

<a id="inv-version-1"></a>
### INV-VERSION-1 — Every advisory has a complete version log   [High]

**Statement.** Every `Advisory` has at least one `AdvisoryVersion` row, seeded
at creation (v1) by a `post_save` signal on `Advisory`. Subsequent
payload-visible edits append `v(n+1)` via
`advisories.services.record_advisory_version`. Saves that change only
non-payload fields (`state`, `republish_required`, `access_review_required_at`,
`modified_at`, `ghsa_metadata_synced_at`) do **not** create version rows.
Adding a new field to `Advisory.to_payload()` is therefore load-bearing: the
field will start being versioned automatically.

**Rationale.** Edit history must be complete for auditors and reviewers, but
must not be polluted by workflow state flips that don't change content. Pairing
"the post_save signal seeds v1" with "explicit appends on edit" gives the
invariant "the latest version always equals the live row" — relied on by
publish and submit-for-review, which both pin the *latest existing* version
rather than creating a fresh one.

**Enforced in.**
- `advisories/signals.py` — `_ensure_initial_version` post_save handler.
- `advisories/apps.py` — `AdvisoriesConfig.ready` registers the signal.
- `advisories/services.py` — `record_advisory_version` is the only path for
  v(n+1); takes a row lock to serialise concurrent edits.
- `advisories/views.py` — `advisory_edit` and `_advisory_edit_ghsa_linked` call
  `record_advisory_version` after a successful form save.
- `ghsa/services.py` — `sync_single_ghsa` appends a version only when
  `result.changed_field_names` is non-empty (filters out heartbeat syncs).

**Violation impact.** Editorial history either has gaps (missing rows for real
edits) or noise (rows for non-content saves), in either case losing its value
for review and audit.

**Tests.** `advisories/tests/test_versions.py`,
`advisories/tests/test_models.py`.

**Related.** [INV-IMPL-5](#inv-impl-5), [INV-VERSION-2](#inv-version-2),
[INV-CONCURRENCY-2](#inv-concurrency-2), [INV-COMMENT-3](#inv-comment-3).

---

<a id="inv-version-2"></a>
### INV-VERSION-2 — Workflow tasks pin a specific version   [High]

**Statement.** Workflow rows that act on a frozen advisory payload reference a
specific `AdvisoryVersion` via a `PROTECT` foreign key, not the live advisory.
Specifically: `workflows.ReviewTask.version` pins the content the reviewer is
judging; `publication.PublicationTask.version` pins the content that was
exported to OSV/CSAF and pushed to Git. A single `AdvisoryVersion` may be
pinned by multiple tasks (e.g. submit-for-review at v3, publish at v3 with no
intervening edit).

**Rationale.** Reviewers and OSV/CSAF consumers must see the exact frozen
content the workflow was triggered on, not the live row that may have drifted
since. `PROTECT` makes it impossible to remove a pinned version even via raw
ORM, complementing [INV-IMPL-5](#inv-impl-5).

**Enforced in.**
- `workflows/models.py` — `ReviewTask.version` (FK, `on_delete=PROTECT`).
- `publication/models.py` — `PublicationTask.version` (FK, `on_delete=PROTECT`).
- `workflows/services.py` — `submit_for_review` reads
  `advisory_services.latest_version(advisory)` and stores it on the task.
- `publication/services.py` — `publish` reads the latest version and stores it
  on the task.

**Violation impact.** Reviewers approve content that has since changed;
published documents drift from the reviewed/approved version.

**Tests.** `workflows/tests.py::test_submit_for_review_pins_latest_version_and_opens_task`,
`workflows/tests.py::test_resubmission_pins_new_version_and_opens_new_task`,
`publication/tests/test_pipeline.py`.

**Related.** [INV-VERSION-1](#inv-version-1), [INV-VERSION-3](#inv-version-3),
[INV-IMPL-5](#inv-impl-5), [INV-REVIEW-2](#inv-review-2).

---

<a id="inv-version-3"></a>
### INV-VERSION-3 — OSV/CSAF generated from an immutable version, not live data   [Critical]

**Statement.** `publication.osv.build_osv` and `publication.csaf.build_csaf` read
from the immutable `AdvisoryVersion.payload` pinned on the `PublicationTask`,
never from the live `Advisory` row. The validated outputs are persisted to
`publication.PublicationArtifact` rows (one per task per kind) and then pushed.

**Rationale.** Ensures the published JSON exactly matches the version pinned at
publish time, even if the advisory is concurrently edited (which would append a
new version without changing the pinned one).

**Enforced in.**
- `publication/osv.py`, `publication/csaf.py` — builders accept an
  `AdvisoryVersion` and read `.payload`.
- `publication/tasks.py` — passes `task.version` to the builders and persists
  the result to `PublicationArtifact`.

**Violation impact.** Published JSON drifts from the version that was reviewed /
pinned for publishing.

**Tests.** `publication/tests/test_osv.py`, `publication/tests/test_csaf.py`,
`publication/tests/test_pipeline.py`.

**Related.** [INV-VERSION-1](#inv-version-1), [INV-VERSION-2](#inv-version-2),
[INV-LIFECYCLE-3](#inv-lifecycle-3), [INV-IMPL-5](#inv-impl-5).

---

## 6. Secret & token redaction

<a id="inv-secret-1"></a>
### INV-SECRET-1 — No tokens in errors   [Critical]

**Statement.** Strings stored in `PublicationTask.last_error` and audit `metadata`
never contain raw `https://x-access-token:...@...` URLs, bearer tokens, or
private-key contents. All such strings pass through
`publication.git_service._redact` (Git contexts) or
`audit.services.redact_secrets` (everything else) first.

**Rationale.** Errors propagate from network/git tracebacks to the admin console
and into e-mail; tokens embedded there would leak immediately.

**Enforced in.**
- `publication/git_service.py` — `_redact`.
- `publication/services.py` — `mark_failed` redacts before saving.
- `audit/services.py` — `record` and friends redact every value.

**Violation impact.** Token leak to admin UI, audit log, or downstream e-mail.

**Tests.** `publication/tests/test_git_service.py`, `audit/test_redact_ghsa_secrets.py`.

**Related.** [INV-AUDIT-2](#inv-audit-2), [INV-SECRET-3](#inv-secret-3).

---

<a id="inv-secret-2"></a>
### INV-SECRET-2 — Tokenised URLs and SSH key paths never persisted   [Critical]

**Statement.** Token-embedded clone URLs exist only in process memory for the
duration of a `publish_files` call. `GIT_SSH_COMMAND` is set in the environment
only inside the `_ssh_env` context manager and restored / unset afterwards. Neither
is written to any model.

**Rationale.** Even in-memory exposure has to be bounded; persistence makes a
single forensic dump catastrophic.

**Enforced in.**
- `publication/git_service.py` — `_embed_token` is transient; `_ssh_env` is a
  context manager that restores `GIT_SSH_COMMAND` on exit.

**Violation impact.** Long-lived tokens / key paths accessible via DB dump or env
inspection of long-running workers.

**Tests.** `publication/tests/test_git_service.py`.

**Related.** [INV-SECRET-1](#inv-secret-1), [INV-PUB-2](#inv-pub-2).

---

<a id="inv-secret-3"></a>
### INV-SECRET-3 — Notification bodies are redacted   [High]

**Statement.** E-mails about publication failures include only the redacted
`last_error`, never the raw error string.

**Rationale.** E-mail is external; forwards, archives, and gateway logs are out of
our control.

**Enforced in.**
- `notifications/tasks.py` — pulls from the already-redacted `last_error`.
- `publication/tasks.py` — passes the redacted `last_error` into the notification.

**Violation impact.** Token leak via e-mail.

**Tests.** `publication/tests/test_pipeline.py`.

**Related.** [INV-SECRET-1](#inv-secret-1), [INV-AUDIT-2](#inv-audit-2).

---

## 7. Public intake & triage safety

<a id="inv-intake-1"></a>
### INV-INTAKE-1 — Honeypot never creates an advisory   [Critical]

**Statement.** A honeypot trip on the public form creates a `HoneypotSubmission`
row (for spam analysis) and renders the same success page as a real submission.
It does *not* create an `Advisory` with `state=triage`.

**Rationale.** Bots must learn nothing from response timing or content; identical
responses make probing useless.

**Enforced in.**
- `intake/forms.py` — honeypot field.
- `intake/views.py` — honeypot branch persists `HoneypotSubmission` only.
- `intake/models.py` — `HoneypotSubmission`.

**Violation impact.** Spam advisories created; success-page differentiation gives
bots a signal.

**Tests.** `intake/tests/test_views_public.py`.

**Related.** [INV-LIFECYCLE-2](#inv-lifecycle-2).

---

<a id="inv-intake-2"></a>
### INV-INTAKE-2 — No reporter-email field on the public form; anonymous reports cannot be re-associated   [Critical]

**Statement.** The public intake form has **no free-text email field**. Reporter
identity is derived only from OIDC-authenticated session (then stored as
`reporter_user`). Anonymous reports cannot be claimed or re-associated later by
matching email.

**Rationale.** A free-text email field invites impersonation ("I'll submit
anonymously, then log in as a different account and claim credit"). Removing the
field removes the attack surface.

**Enforced in.**
- `intake/forms.py` — no email field.
- `advisories/services.py` — `submit_triage_report` sets `reporter_user` from the
  authenticated request only.

**Violation impact.** Reporter impersonation; broken provenance for triage.

**Tests.** `intake/tests/test_views_public.py`, `advisories/tests/test_triage.py`.

**Related.** [INV-INTAKE-3](#inv-intake-3), [INV-PRIVACY-3](#inv-privacy-3).

---

<a id="inv-intake-3"></a>
### INV-INTAKE-3 — Authenticated reporters auto-receive a viewer grant   [High]

**Statement.** When an authenticated user files a triage report, the service
issues an `AdvisoryAccessGrant(permission=viewer)` on the new row so the reporter
can track it from their dashboard. Anonymous reporters receive no grant.

**Rationale.** Reporters need read access to follow up; viewer is the minimum safe
level on an untrusted triage row (see [INV-AUTH-5](#inv-auth-5)).

**Enforced in.**
- `advisories/services.py` — `submit_triage_report` issues the viewer grant.

**Violation impact.** Either no access (reporter loses track) or too much access
(reporter can mutate the untrusted row).

**Tests.** `advisories/tests/test_triage.py`.

**Related.** [INV-AUTH-5](#inv-auth-5), [INV-INTAKE-2](#inv-intake-2).

---

<a id="inv-intake-4"></a>
### INV-INTAKE-4 — `unsorted` reports default to admin routing   [High]

**Statement.** Triage reports filed against the `unsorted` sentinel project
automatically set `AdvisoryIntakeMetadata.needs_admin_routing=True`.

**Rationale.** When the reporter does not know the right project, the report must
land with admins for re-routing, not in some default team's queue.

**Enforced in.**
- `advisories/services.py` — `submit_triage_report` sets the flag when
  `project.slug == UNSORTED_PROJECT_SLUG`.
- `advisories/permissions.py` — `UNSORTED_PROJECT_SLUG`.

**Violation impact.** Misrouted reports get suppressed by the wrong team.

**Tests.** `advisories/tests/test_triage.py`.

**Related.** [INV-AUTH-6](#inv-auth-6), [INV-PROJECT-2](#inv-project-2).

---

## 8. OIDC identity & group sync

<a id="inv-oidc-1"></a>
### INV-OIDC-1 — Groups re-synced on every login   [Critical]

**Statement.** `AdvisoryHubOIDCBackend.update_user` calls `sync_groups_from_claims`
on every successful login, **replacing** `user.groups` with the set derived from
the configured OIDC claim. There is no group caching across logins. The login
full-replace is the *sole* writer of `user.groups`; the security-team roster sync
([INV-OIDC-5](#inv-oidc-5)) deliberately never touches it, so the two never collide.

**Rationale.** If a user is removed from a group in the IdP, the local mirror must
reflect that on the very next login. Cached or sticky group membership is a
de-escalation hole.

**Enforced in.**
- `accounts/auth.py` — `AdvisoryHubOIDCBackend.update_user`,
  `sync_groups_from_claims`.

**Violation impact.** Demoted users keep elevated access.

**Tests.** `accounts/test_step_up.py` and the broader accounts test suite.

**Related.** [INV-OIDC-2](#inv-oidc-2), [INV-OIDC-3](#inv-oidc-3).

---

<a id="inv-oidc-2"></a>
### INV-OIDC-2 — Authorization reads from the DB mirror, never client input   [Critical]

**Statement.** Predicates such as `is_global_admin` and `is_security_team_member`
consult `user.groups` (the DB mirror); they never read group names from request
parameters, headers, or form bodies.

**Rationale.** The DB mirror is what `sync_groups_from_claims` keeps fresh; trusting
client-side group claims would let attackers forge their group set.

**Enforced in.**
- `advisories/permissions.py` — `is_global_admin`, `is_security_team_member`.

**Violation impact.** Trivially forged privilege escalation.

**Tests.** `advisories/tests/test_permissions.py`.

**Related.** [INV-OIDC-1](#inv-oidc-1), [INV-AUTH-1](#inv-auth-1).

---

<a id="inv-oidc-3"></a>
### INV-OIDC-3 — `is_staff` / `is_superuser` track admin-group membership   [High]

**Statement.** On every login, the OIDC backend sets `user.is_staff` and
`user.is_superuser` equal to admin-group membership. Removal from
`OIDC_ADMIN_GROUP` clears both flags on the next login.

**Rationale.** Django admin access must follow IdP demotion without manual
intervention.

**Enforced in.**
- `accounts/auth.py` — `_apply_claims`.

**Violation impact.** Demoted admins retain `/django-admin/` access.

**Tests.** Accounts test suite.

**Related.** [INV-OIDC-1](#inv-oidc-1).

---

<a id="inv-oidc-4"></a>
### INV-OIDC-4 — SPN-form group filter   [Medium]

**Statement.** `sync_groups_from_claims` filters claim values to those that look
like SPNs (contain `@`), dropping UUIDs and Kanidm internal prefixes so the
Django `Group` table stays clean.

**Rationale.** Kanidm emits a group multiple times by different identifiers; the
filter prevents duplicate `Group` rows that would never match
`is_security_team_member`.

**Enforced in.**
- `accounts/auth.py` — `sync_groups_from_claims`.

**Violation impact.** Group lookup misses; spurious `Group` rows clutter admin.

**Tests.** Accounts test suite.

**Related.** [INV-OIDC-1](#inv-oidc-1).

---

<a id="inv-oidc-5"></a>
### INV-OIDC-5 — Provisioned (shadow) users carry no authorization   [High]

**Statement.** A `User` with `is_provisioned=True` is a *shadow* account
pre-provisioned by the security-team roster sync
(`projects.services.sync_security_team_roster`) for a member who has never logged
in. A shadow user is **never** added to any `auth.Group`, never resolves to any
advisory permission, and is excluded from owner/member displays. The roster sync
never writes `user.groups`. The flag is cleared exactly once, on the member's first
OIDC login (`accounts.auth.AdvisoryHubOIDCBackend._apply_claims`), after which
authorization is governed entirely by the OIDC group claim
([INV-OIDC-1](#inv-oidc-1)) — never by the roster.

**Rationale.** The roster exists so security-team members are reachable by
notification before their first login (see [INV-ROSTER-1](#inv-roster-1)). Coupling
that reach to group membership would silently grant `owner` to people who never
authenticated, violating "owner is derived" ([INV-AUTH-3](#inv-auth-3)). Keeping
shadows out of every group makes "no access" true by construction and sidesteps the
login full-replace ([INV-OIDC-1](#inv-oidc-1)) ever fighting the sync.

**Enforced in.**
- `projects/services.py` — `sync_security_team_roster` / `_provision_or_link_shadow`
  (creates shadows with no group membership).
- `accounts/auth.py` — `_apply_claims` clears `is_provisioned` on first login.

**Violation impact.** A never-authenticated identity gains `owner`/`collaborator`
access; or the login full-replace silently wipes roster-driven membership.

**Tests.** `projects/test_roster_sync.py`, `accounts/test_roster_linking.py`.

**Related.** [INV-OIDC-1](#inv-oidc-1), [INV-AUTH-3](#inv-auth-3),
[INV-ROSTER-1](#inv-roster-1).

---

<a id="inv-roster-1"></a>
### INV-ROSTER-1 — Roster notification reach is default-set, per-project, never internal   [Medium]

**Statement.** Active roster shadow members of a project
(`SecurityTeamRosterEntry`, `soft_removed_at IS NULL`, linked user
`is_provisioned=True`) are eligible notification recipients **only for their own
project's advisories**, with the *default*-preference set of a security-team member
— `advisory_created`, the lifecycle events, and `@`-mentions (including a `@team`
mention of the project's security group). They are always dropped from **internal**
comments by the `can_see_internal_comment` floor, and (with default preferences) do
not receive every ordinary comment. Roster membership authorizes only this email
channel; it confers no in-app view/owner access ([INV-OIDC-5](#inv-oidc-5)).

**Rationale.** Reaching the full security team — including members who have never
logged in — is the whole point of the roster ([TODO/INV-OIDC-5](#inv-oidc-5)). The
mention/notification email contains advisory content, so reach is deliberately a
disclosure to a rostered Eclipse-security-team email; it is bounded to that team's
own project and excludes internal comments, which remain collaborator+ only.

**Enforced in.**
- `notifications/recipients.py` — `_roster_shadow_members` + the `filter_for_event`
  branches (mention path gated on `mentioned_group_ids`; internal floor applies).
- `notifications/tasks.py` / `comments/views.py` — thread `mentioned_group_ids`.

**Violation impact.** Internal-comment content leaks to a never-logged-in email, or
a shadow is notified about another project's advisory.

**Tests.** `notifications/tests.py` (shadow-reach + leak guards).

**Related.** [INV-OIDC-5](#inv-oidc-5), [INV-AUTH-1](#inv-auth-1),
[INV-PRIVACY-2](#inv-privacy-2).

---

## 9. Publication pipeline integrity

<a id="inv-pub-1"></a>
### INV-PUB-1 — Fresh `TemporaryDirectory` per publication   [Critical]

**Statement.** Every call to `publication.git_service.publish_files` opens a new
`tempfile.TemporaryDirectory()` and clones into it. There is no persistent shared
checkout.

**Rationale.** Two concurrent publications cannot race on the same working tree;
no stale state from a previous failed publication can affect the next one.

**Enforced in.**
- `publication/git_service.py` — `publish_files` uses `TemporaryDirectory`.

**Violation impact.** Race-conditioned commits, partial pushes, or accidental
mixing of artifacts across advisories.

**Tests.** `publication/tests/test_git_service.py`, `publication/tests/test_pipeline.py`.

**Related.** [INV-CONCURRENCY-1](#inv-concurrency-1), [INV-PUB-3](#inv-pub-3).

---

<a id="inv-pub-2"></a>
### INV-PUB-2 — SSH and token auth are mutually exclusive   [Medium]

**Statement.** `PUB_REPO_AUTH` selects exactly one of `ssh` or `token`. The Git
service applies only the chosen method.

**Rationale.** Reduces credential surface; eliminates ambiguity about which key
was actually used.

**Enforced in.**
- `publication/git_service.py` — `_ssh_env` / `_embed_token` are called in
  separate branches of `publish_files`.

**Violation impact.** Hard-to-diagnose auth failures and credential confusion.

**Tests.** `publication/tests/test_git_service.py`.

**Related.** [INV-SECRET-2](#inv-secret-2).

---

<a id="inv-pub-3"></a>
### INV-PUB-3 — Shallow clones   [Medium]

**Statement.** Publication clones use `depth=1`.

**Rationale.** Reduces network use; avoids pulling unrelated history into the
worker (a defence-in-depth measure if the repo ever contained sensitive history).

**Enforced in.**
- `publication/git_service.py` — `publish_files` passes `depth=1`.

**Violation impact.** Slow publications and unnecessary local history exposure.

**Tests.** `publication/tests/test_git_service.py`.

**Related.** [INV-PUB-1](#inv-pub-1).

---

<a id="inv-pub-4"></a>
### INV-PUB-4 — State flip and task outcome share a transaction   [Critical]

**Statement.** The publication task wraps the state flip, `PublicationTask`
finalisation, `Advisory.published_at`, `republish_required=False`, and the audit
emissions in a single `transaction.atomic` block guarded by
`Advisory.objects.select_for_update`.

**Rationale.** Avoids the half-published state where one of these writes succeeds
and another rolls back.

**Enforced in.**
- `publication/tasks.py` — `run_publication`.

**Violation impact.** Inconsistent published state vs. task status; missing audit
trail for actual publications.

**Tests.** `publication/tests/test_pipeline.py`.

**Related.** [INV-LIFECYCLE-3](#inv-lifecycle-3), [INV-CONCURRENCY-2](#inv-concurrency-2).

---

<a id="inv-pub-5"></a>
### INV-PUB-5 — Celery enqueue via `transaction.on_commit`   [High]

**Statement.** `publication.services.publish` enqueues `run_publication.delay`
inside `transaction.on_commit` so a rolled-back outer transaction never leaves a
stray queued task.

**Rationale.** Eliminates "ghost" publications when the calling view rolls back.

**Enforced in.**
- `publication/services.py` — `transaction.on_commit(lambda: run_publication.delay(...))`.

**Violation impact.** Tasks that try to publish a version that does not exist
or an advisory whose state was meant to be unchanged.

**Tests.** `publication/tests/test_pipeline.py`.

**Related.** [INV-PUB-4](#inv-pub-4).

---

<a id="inv-pub-6"></a>
### INV-PUB-6 — OSV and CSAF documents validated before push   [High]

**Statement.** OSV and CSAF documents are validated against the vendored
JSON-Schemas in `publication/schemas/` before being written, committed, or pushed.

**Rationale.** Public consumers expect schema-conformant output; broken JSON
crashes downstream pipelines and damages trust.

**Enforced in.**
- `publication/osv.py`, `publication/csaf.py` — validation steps.
- `publication/tasks.py` — calls validate before persistence.

**Violation impact.** Invalid documents on the public repo; consumer-CI breakage.

**Tests.** `publication/tests/test_osv.py`, `publication/tests/test_csaf.py`.

**Related.** [INV-VERSION-3](#inv-version-3).

---

## 10. Permission resolution & publication eligibility

<a id="inv-perm-1"></a>
### INV-PERM-1 — Mature publishers may publish without top-level review   [High]

**Statement.** When `advisory.project.is_mature_publisher` is true, members of the
project's security team may publish even without `review_status=approved`. Other
projects require approval or global admin status.

**Rationale.** Reduces friction for trusted teams while keeping a guard rail
(review) on newer ones.

**Enforced in.**
- `advisories/permissions.py` — `can_publish`.
- `projects/models.py` — `Project.is_mature_publisher`.

**Violation impact.** Either friction for mature teams or unreviewed publications
from new ones.

**Tests.** `advisories/tests/test_permissions.py`, `publication/tests/test_pipeline.py`.

**Related.** [INV-PERM-2](#inv-perm-2), [INV-REVIEW-4](#inv-review-4).

---

<a id="inv-perm-2"></a>
### INV-PERM-2 — Mature-publisher status lives on `Project`   [High]

**Statement.** Mature-publisher status is a boolean on the `Project` row, not a
Django group, OIDC group, or environment variable.

**Rationale.** Single source of truth that admins can flip from the admin console.

**Enforced in.**
- `projects/models.py` — `Project.is_mature_publisher`.
- `advisories/permissions.py` — `can_publish` reads `advisory.project.is_mature_publisher`.

**Violation impact.** Drift between configuration sources, surprise behaviour.

**Tests.** `advisories/tests/test_permissions.py`.

**Related.** [INV-PERM-1](#inv-perm-1).

---

<a id="inv-perm-3"></a>
### INV-PERM-3 — No publish while review is submitted   [High]

**Statement.** When `review_status=submitted`, `can_publish` returns `False` for
everyone, including global admins.

**Rationale.** Avoid publishing the wrong snapshot while reviewers are looking at
a different version.

**Enforced in.**
- `advisories/permissions.py` — `can_publish`.

**Violation impact.** Race between admin publish and reviewer decision; published
content mismatches reviewed content.

**Tests.** `advisories/tests/test_permissions.py`.

**Related.** [INV-REVIEW-2](#inv-review-2).

---

## 11. Access grants & invitations

<a id="inv-access-1"></a>
### INV-ACCESS-1 — One grant per (advisory, principal)   [High]

**Statement.** At most one `AdvisoryAccessGrant` exists per `(advisory,
principal_type, principal_id)` tuple. Updates change the permission in place.

**Rationale.** Simplifies resolution and prevents conflicting grants for the
same principal.

**Enforced in.**
- `access/models.py` — `UniqueConstraint` (or `unique_together`).

**Violation impact.** Permission resolution ambiguity for duplicate grants.

**Tests.** `access/tests.py`.

**Related.** [INV-AUTH-4](#inv-auth-4).

---

<a id="inv-access-2"></a>
### INV-ACCESS-2 — Invitation email match is case-insensitive   [High]

**Statement.** `PendingInvitation` redemption matches recipient e-mail
case-insensitively (`email__iexact`).

**Rationale.** Users routinely log in with different e-mail casings than the
sender used; an exact-case match would deny legitimate invitations.

**Enforced in.**
- `access/services.py` — `redeem_invitations_for_user`.

**Violation impact.** Legitimate invitations cannot be redeemed.

**Tests.** `access/tests.py`.

**Related.** [INV-ACCESS-3](#inv-access-3).

---

<a id="inv-access-3"></a>
### INV-ACCESS-3 — Invitations expire   [Medium]

**Statement.** `PendingInvitation` rows carry an expiry (default 14 days). Expired
invitations cannot be redeemed.

**Rationale.** Limits the window during which a leaked invitation token is
useful.

**Enforced in.**
- `access/models.py` — `PendingInvitation` with `is_expired` predicate.
- `access/services.py` — redemption checks `is_expired`.

**Violation impact.** Invitations remain redeemable forever after leak.

**Tests.** `access/tests.py`.

**Related.** [INV-ACCESS-2](#inv-access-2).

---

<a id="inv-access-4"></a>
### INV-ACCESS-4 — Grant API rejects `owner`   [Critical]

**Statement.** Service-layer grant and invitation entry points reject
`permission="owner"`. The model's `Permission.choices` does not include it.

**Rationale.** See [INV-AUTH-3](#inv-auth-3) — owner is structural.

**Enforced in.**
- `access/services.py` — `_validate_grantable_permission`.
- `access/models.py` — `Permission.choices`.

**Violation impact.** Trivial owner escalation via the grant API.

**Tests.** `access/tests.py`.

**Related.** [INV-AUTH-3](#inv-auth-3).

---

<a id="inv-access-5"></a>
### INV-ACCESS-5 — Grant changes are audited   [High]

**Statement.** Every grant create / update / revoke and every invitation
create / redeem / revoke emits an audit entry.

**Rationale.** Access changes are the most sensitive non-state-machine action;
the audit trail must answer "who gave whom access to what, when?"

**Enforced in.**
- `access/services.py` — emits `ACCESS_GRANTED` / `ACCESS_REVOKED` /
  `INVITATION_*` actions.

**Violation impact.** Silent access changes; broken forensic record.

**Tests.** `access/tests.py`, `audit/tests.py`.

**Related.** [INV-AUDIT-3](#inv-audit-3).

---

## 12. Comments

<a id="inv-comment-1"></a>
### INV-COMMENT-1 — `is_internal` is set at creation   [High]

**Statement.** `AdvisoryComment.is_internal` is fixed when the comment is created
and is not mutated afterwards.

**Rationale.** Flipping internal/public after the fact would silently broaden or
narrow the visibility of an already-readable comment, including by past readers
who already saw it.

**Enforced in.**
- `comments/services.py` — comment editing changes body, never `is_internal`.

**Violation impact.** Sensitive internal discussion becomes externally visible
(or vice versa).

**Tests.** `comments/tests.py`.

**Related.** [INV-COMMENT-2](#inv-comment-2).

---

<a id="inv-comment-2"></a>
### INV-COMMENT-2 — Internal comment visibility is re-checked at read time   [High]

**Statement.** Rendering a comment to a user goes through `can_see_internal_comment`
(or an equivalent gate) at *display* time, not at *post* time. A user who lost
collaborator access stops seeing internal comments immediately.

**Rationale.** Revoked access takes effect now, not at the next refresh of some
cached view.

**Enforced in.**
- `advisories/permissions.py` — `can_see_internal_comment`.
- `comments/views.py` — applies the predicate before rendering.

**Violation impact.** Ex-collaborators continue to see internal comments.

**Tests.** `comments/tests.py`.

**Related.** [INV-COMMENT-1](#inv-comment-1), [INV-PRIVACY-2](#inv-privacy-2).

---

<a id="inv-comment-3"></a>
### INV-COMMENT-3 — Comment edits append immutable versions   [Medium]

**Statement.** Editing a comment writes a new `CommentVersion` row. Old versions
are never updated or deleted.

**Rationale.** Preserves the edit history for auditors and other readers.

**Enforced in.**
- `comments/models.py` — `CommentVersion`.
- `comments/services.py` — edit path inserts a new row, never updates.

**Violation impact.** Loss of comment-edit history.

**Tests.** `comments/tests.py`.

**Related.** [INV-IMPL-3](#inv-impl-3), [INV-VERSION-1](#inv-version-1) (the
same shape applied to advisories).

---

<a id="inv-comment-4"></a>
### INV-COMMENT-4 — Redaction is irreversible   [Medium]

**Statement.** A redacted comment keeps its row (preserving its place in the
timeline) but the visible body becomes empty. `redacted_at` / `redacted_by`
are stamped once and not cleared.

**Rationale.** Redaction is a deliberate, terminal removal of content; an undo
would defeat the purpose.

**Enforced in.**
- `comments/models.py` — `redacted_at`, `redacted_by`, `is_redacted`,
  `visible_body`.
- `comments/services.py` — redact path is one-way.

**Violation impact.** Redacted content reappears or the timeline order breaks.

**Tests.** `comments/tests.py`.

**Related.** [INV-COMMENT-3](#inv-comment-3).

---

## 13. Concurrency & race conditions

<a id="inv-concurrency-1"></a>
### INV-CONCURRENCY-1 — Single in-flight publication per advisory   [High]

**Statement.** `publication.services.publish` takes a row lock with
`Advisory.objects.select_for_update` and raises `PublicationInProgress` if a
queued or running `PublicationTask` already exists for the advisory.

**Rationale.** Serialises publication attempts so two pushes do not race for the
same path in the publication repo.

**Enforced in.**
- `publication/services.py` — `publish`.

**Violation impact.** Lost or out-of-order commits in the publication repo.

**Tests.** `publication/tests/test_pipeline.py`.

**Related.** [INV-PUB-1](#inv-pub-1), [INV-PUB-4](#inv-pub-4).

---

<a id="inv-concurrency-2"></a>
### INV-CONCURRENCY-2 — Version writes and state flips are atomic   [Critical]

**Statement.** All operations that flip an advisory state, append an
`AdvisoryVersion`, or pin a version on a workflow task run inside
`transaction.atomic`. Failure rolls back the whole bundle.

**Rationale.** Eliminates "state flipped but version missing" or "audit lost"
half-states. Concurrent edits cannot race to compute the same next version
number because `record_advisory_version` takes a `select_for_update` row lock
on the advisory before reading the max version.

**Enforced in.**
- `advisories/services.py` — `record_advisory_version` is `@transaction.atomic`
  and holds an `Advisory` row lock while computing the next version number.
- `publication/services.py` — `publish` runs inside `transaction.atomic` and
  pins the version under the same row lock.
- `publication/tasks.py` — final state flip is wrapped in `transaction.atomic`.

**Violation impact.** Partial writes leave the data in an inconsistent state
that cannot be reasoned about; concurrent edits could collide on the
`(advisory, version)` unique constraint.

**Tests.** `publication/tests/test_pipeline.py`, `advisories/tests/test_models.py`,
`advisories/tests/test_versions.py`.

**Related.** [INV-PUB-4](#inv-pub-4), [INV-LIFECYCLE-3](#inv-lifecycle-3),
[INV-VERSION-1](#inv-version-1).

---

## 14. CVE request workflow

<a id="inv-cve-1"></a>
### INV-CVE-1 — One open CVE request per advisory   [High]

**Statement.** At most one `CveRequestTask` with `status=queued` exists per
advisory at any time, enforced by a DB `UniqueConstraint`.

**Rationale.** Prevents duplicate CVE reservations and stops users from spamming
the queue.

**Enforced in.**
- `workflows/models.py` — `UniqueConstraint` on `(advisory, status=queued)`.

**Violation impact.** Duplicate / conflicting CVE requests.

**Tests.** `workflows/tests.py`.

**Related.** [INV-CVE-2](#inv-cve-2), [INV-CVE-3](#inv-cve-3).

---

<a id="inv-cve-2"></a>
### INV-CVE-2 — `assigned_cve_id` is write-once   [High]

**Statement.** Once an advisory has a non-empty `assigned_cve_id`,
`can_request_cve` returns `False`. The ID is changed only via deliberate admin
unassign flow.

**Rationale.** A CVE ID, once reserved or assigned, must not silently move to a
different advisory.

**Enforced in.**
- `advisories/permissions.py` — `can_request_cve`.
- `advisories/models.py` — `assigned_cve_id` with validator.

**Violation impact.** Reassignment of a CVE to the wrong advisory; downstream
data inconsistency.

**Tests.** `workflows/tests.py`, `advisories/tests/test_permissions.py`.

**Related.** [INV-CVE-1](#inv-cve-1), [INV-ID-3](#inv-id-3).

---

<a id="inv-cve-3"></a>
### INV-CVE-3 — CVE-request ban is admin-only   [Medium]

**Statement.** `Advisory.cve_requests_banned` is set only by admins (e.g. after a
rejected request) and unbanned only by admins.

**Rationale.** Prevents users from bypassing a rejection by re-requesting; admins
remain in control.

**Enforced in.**
- `advisories/models.py` — `cve_requests_banned` field.
- `advisories/permissions.py` — `can_request_cve` honours the ban.
- Admin-console flow — ban / unban surface for admins only.

**Violation impact.** Users escape rejection by spamming requests.

**Tests.** `advisories/tests/test_permissions.py`, `workflows/tests.py`.

**Related.** [INV-CVE-1](#inv-cve-1).

---

## 15. Identifiers & validation

<a id="inv-id-1"></a>
### INV-ID-1 — Public advisory ID is canonical and immutable   [High]

**Statement.** The public advisory ID matches the regex defined in
`advisories/identifiers.py` (`ECL-…-…-…` using a confusion-resistant alphabet)
and does not change after creation.

**Rationale.** Stable, unambiguous identifiers used in URLs, OSV/CSAF, and
external references. The reduced alphabet avoids the visual collisions of `0/O`,
`1/I/L`, etc.

**Enforced in.**
- `advisories/identifiers.py` — generator and regex.
- `advisories/validators.py` — `validate_advisory_id`.
- `advisories/models.py` — generated in `Advisory.save`, never updated.

**Violation impact.** Broken external links; CVE / OSV correlation fails.

**Tests.** `advisories/tests/test_identifiers.py`, `advisories/tests/test_validators.py`.

**Related.** [INV-LIFECYCLE-5](#inv-lifecycle-5), [INV-IMPL-4](#inv-impl-4).

---

<a id="inv-id-2"></a>
### INV-ID-2 — `ghsa_id` is unique when non-empty   [High]

**Statement.** A DB constraint enforces uniqueness on `ghsa_id` for non-empty
values. Native (non-GHSA) advisories share the empty-string sentinel.

**Rationale.** A given GHSA identifier must map to exactly one AdvisoryHub
advisory.

**Enforced in.**
- `advisories/models.py` — `UniqueConstraint` with non-empty condition.

**Violation impact.** Diverging GHSA-linked advisories.

**Tests.** `advisories/tests/test_models.py`, `ghsa/tests/test_services.py`.

**Related.** [INV-ID-1](#inv-id-1).

---

<a id="inv-id-3"></a>
### INV-ID-3 — `assigned_cve_id` matches `CVE-YYYY-NNNN…`   [Medium]

**Statement.** The CVE ID validator rejects values that do not match the CVE
regex.

**Rationale.** Catches typos and accidental concatenation at the input boundary.

**Enforced in.**
- `advisories/validators.py` — `validate_cve_id`.
- `advisories/models.py` — `assigned_cve_id` references the validator.

**Violation impact.** Malformed CVE IDs in OSV/CSAF output.

**Tests.** `advisories/tests/test_validators.py`.

**Related.** [INV-CVE-2](#inv-cve-2).

---

## 16. Project structure

<a id="inv-project-1"></a>
### INV-PROJECT-1 — Security team is a Django Group   [Medium]

**Statement.** Each `Project` has a `security_team` foreign key to a Django
`Group`. Project ownership derives from membership in that group.

**Rationale.** Makes OIDC group → project mapping uniform and avoids ad-hoc
membership tables.

**Enforced in.**
- `projects/models.py` — `Project.security_team`.

**Violation impact.** Duplicated membership logic; broken OIDC mapping.

**Tests.** `projects` is exercised across the wider test suite (no dedicated
tests).

**Related.** [INV-OIDC-2](#inv-oidc-2), [INV-AUTH-3](#inv-auth-3).

---

<a id="inv-project-2"></a>
### INV-PROJECT-2 — `unsorted` is the routing sentinel   [High]

**Statement.** A singleton `Project` with `slug="unsorted"` exists. Its
`security_team` is the admin group, so admin routing falls out of normal
permission resolution. The constant lives in
`advisories.permissions.UNSORTED_PROJECT_SLUG`.

**Rationale.** Misrouted reports must always have a home; making it a real
project lets the permission machinery flow naturally.

**Enforced in.**
- `advisories/permissions.py` — `UNSORTED_PROJECT_SLUG`.
- `advisories/services.py` — `submit_triage_report` flags `needs_admin_routing`
  when targeting unsorted.
- Seed / migration ensures the project exists.

**Violation impact.** Unsorted reports land with no clear owner.

**Tests.** `advisories/tests/test_triage.py`.

**Related.** [INV-AUTH-6](#inv-auth-6), [INV-INTAKE-4](#inv-intake-4).

---

## 17. Implicit / structural invariants

<a id="inv-impl-1"></a>
### INV-IMPL-1 — `Advisory.delete()` is blocked   [Critical]

**Statement.** `Advisory.delete()` and `AdvisoryQuerySet.delete()` raise
`PermissionError`. A Postgres trigger (advisories migration `0003_advisory_no_delete_trigger`)
adds DB-level enforcement. Seed / reset tooling must use the explicit
`_unsafe_dev_reset_bypass()` context manager.

**Rationale.** Advisory identity is referenced from audit, comments,
`AdvisoryVersion`, and (after publish) the publication repo. Deleting would
orphan dependents and destroy history.

**Enforced in.**
- `advisories/models.py` — `Advisory.delete`, `AdvisoryQuerySet.delete`,
  `_unsafe_dev_reset_bypass`.
- `advisories/migrations/0003_advisory_no_delete_trigger.py`.

**Violation impact.** Orphaned audit history; references to a non-existent
advisory in published artefacts.

**Tests.** `advisories/tests/test_models.py`.

**Related.** [INV-IMPL-5](#inv-impl-5), [INV-AUDIT-1](#inv-audit-1).

---

<a id="inv-impl-2"></a>
### INV-IMPL-2 — `AuditLogEntry.delete()` is blocked   [Critical]

**Statement.** `AuditLogEntry.delete()` raises `PermissionError`. The DB trigger
`audit_log_no_delete` enforces the same at the database layer.

**Rationale.** The audit log is the system of record for governance actions; any
deletion path is itself a vulnerability.

**Enforced in.**
- `audit/models.py` — `AuditLogEntry.delete`.
- `audit/migrations/0002_append_only_trigger.py`.

**Violation impact.** Tampering with the audit trail.

**Tests.** `audit/tests.py`, `audit/test_retention.py`.

**Related.** [INV-AUDIT-1](#inv-audit-1).

---

<a id="inv-impl-3"></a>
### INV-IMPL-3 — `CommentVersion` rows are append-only   [High]

**Statement.** `CommentVersion.save()` rejects updates of an existing row.
`delete()` is also blocked.

**Rationale.** Comment edit history must remain inspectable.

**Enforced in.**
- `comments/models.py` — `CommentVersion`.

**Violation impact.** Loss of edit history.

**Tests.** `comments/tests.py`.

**Related.** [INV-COMMENT-3](#inv-comment-3), [INV-IMPL-5](#inv-impl-5) (the
same shape applied to advisories).

---

<a id="inv-impl-4"></a>
### INV-IMPL-4 — Advisory ID generation retries on collision   [Medium]

**Statement.** `Advisory._generate_unique_id` retries up to `MAX_ID_RETRIES` (8)
times on collision and raises if it cannot allocate a unique ID. Astronomically
unlikely in practice; the guard is explicit.

**Rationale.** Defence-in-depth against a pathological RNG / lock pattern.

**Enforced in.**
- `advisories/models.py` — `MAX_ID_RETRIES`, `_generate_unique_id`.

**Violation impact.** Save loop or duplicate ID.

**Tests.** `advisories/tests/test_identifiers.py`.

**Related.** [INV-ID-1](#inv-id-1).

---

<a id="inv-impl-5"></a>
### INV-IMPL-5 — `AdvisoryVersion` rows are append-only   [Critical]

**Statement.** `AdvisoryVersion.save()` raises `PermissionError` when called on
an existing row (`pk is not None`); `AdvisoryVersion.delete()` raises
unconditionally. Enforcement is application-layer only — there is no Postgres
trigger.

**Rationale.** The version log is the system of record for every editorial
change to an advisory. Mutating an existing row or removing one would silently
rewrite history. Workflow tasks (`ReviewTask.version`, `PublicationTask.version`)
also `PROTECT`-FK into this table (see [INV-VERSION-2](#inv-version-2)), so a
version that was ever pinned cannot be removed even via raw ORM.

**Enforced in.**
- `advisories/models.py` — `AdvisoryVersion.save`, `AdvisoryVersion.delete`.
- `workflows/models.py` — `ReviewTask.version` is `PROTECT`-FK.
- `publication/models.py` — `PublicationTask.version` is `PROTECT`-FK.

**Violation impact.** Loss of editorial history; review/publication records
pointing at a payload that no longer matches what was approved or pushed.

**Tests.** `advisories/tests/test_models.py` (existing-row save / delete raise);
`advisories/tests/test_versions.py`.

**Related.** [INV-VERSION-1](#inv-version-1), [INV-VERSION-2](#inv-version-2),
[INV-IMPL-1](#inv-impl-1), [INV-IMPL-3](#inv-impl-3) (the same shape for
`CommentVersion`).

---

## 18. Privacy & data sensitivity

<a id="inv-privacy-1"></a>
### INV-PRIVACY-1 — Advisories without access are not enumerable   [High]

**Statement.** Views, APIs, and list filters scope advisory querysets to rows the
caller can see, regardless of state. Counts, search results, and pagination
totals never leak the existence of advisories the user has no access to.

**Rationale.** Otherwise an attacker could probe by ID, list size, or filter
result to confirm that a sensitive advisory exists.

**Enforced in.**
- `advisories/views.py`, `api/views.py` — queryset filtering by
  `resolved_permission`.

**Violation impact.** Disclosure-by-side-channel (count, 404 vs 403 timing,
search auto-complete leakage).

**Tests.** `advisories/tests/test_list_filters.py`, `advisories/tests/test_views.py`,
`api/tests/test_advisories.py`.

**Related.** [INV-AUTH-7](#inv-auth-7).

---

<a id="inv-privacy-2"></a>
### INV-PRIVACY-2 — Notification recipients are re-checked at send time   [High]

**Statement.** Notification tasks re-evaluate recipient access before sending.
Revoked grants drop from the queue.

**Rationale.** Pre-computed mailing lists can race against access revocation;
re-checking at send time honours the latest state.

**Enforced in.**
- `notifications/tasks.py` — recomputes recipients before send.

**Violation impact.** Ex-collaborators continue to receive advisory mail.

**Tests.** Notification flows are exercised across publication and access tests.

**Related.** [INV-COMMENT-2](#inv-comment-2), [INV-AUTH-7](#inv-auth-7).

---

<a id="inv-privacy-3"></a>
### INV-PRIVACY-3 — `reporter_display_name` is display-only   [Medium]

**Statement.** The optional `reporter_display_name` on a triage advisory is used
only for crediting in the UI. It is *never* parsed as an email or used for
authorization decisions.

**Rationale.** It is free-text, unsanitised, and supplied by an untrusted public
form; treating it as identity would be a forgery vector.

**Enforced in.**
- `advisories/models.py` — `Advisory.reporter_display_name`.
- `advisories/services.py` — `submit_triage_report` stores it as plain string;
  authorization paths read `reporter_user`, never `reporter_display_name`.

**Violation impact.** Forged "I am person X" via a display-name string.

**Tests.** `advisories/tests/test_triage.py`.

**Related.** [INV-INTAKE-2](#inv-intake-2).

---

## Appendix A — Adding a new invariant

1. **Is it really an invariant?** Ask whether violating it breaks the security
   model, audit trail, data integrity, or the publication contract. If the
   answer is "we currently happen to do it this way", it is a coding convention,
   not an invariant — put it in `CLAUDE.md` instead.
2. **Pick a category.** Reuse an existing section if possible; only add a new
   category when the new rule does not fit anywhere.
3. **Allocate the next ID.** `INV-<CATEGORY>-N` where `N` is one greater than
   the current highest in that category. **Never reuse a retired ID.**
4. **Add an Index row** in alphabetical / categorical order with a one-line
   statement and severity.
5. **Write the block** with the standard fields (Statement, Rationale, Enforced
   in, Violation impact, Tests, Related). If the test does not yet exist, write
   `_(test pending)_` rather than fabricating one.
6. **Pick a severity tier** using the table at the top.
7. **Link related invariants** in both directions (this document is a small
   graph; broken bidirectional links rot fast).

## Appendix B — Deprecating an invariant

1. Add `[Deprecated YYYY-MM-DD]` to the heading; keep the ID and section.
2. Add a `**Superseded by.**` line pointing to the replacement, if any.
3. Strike through the Statement / Rationale only if it is actively misleading;
   otherwise leave them for historical context.
4. Update the Index row's severity column to `Deprecated`.
5. **Never reuse the ID.** A reference from a four-year-old PR or commit message
   must always resolve to the same rule (active or deprecated).
