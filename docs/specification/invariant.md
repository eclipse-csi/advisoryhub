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
| [INV-WITHDRAW](#inv-withdraw) | A published advisory is withdrawn, never deleted: OSV/CSAF are re-exported marked withdrawn (any assigned CVE re-exported REJECTED) and the row flips to dismissed. | Lifecycle | High |
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
| [INV-AUTH-8](#inv-auth-8) | A banned account is denied login and its live session is dropped on the next request. | Authorization | High |
| [INV-AUTH-9](#inv-auth-9) | Draft admin-reassignment requests are non-locking; the team keeps editing while one is pending. | Authorization | High |
| [INV-MAINT-1](#inv-maint-1) | While maintenance mode is on, only global admins may mutate state; everyone else is paused server-side. | Maintenance | Critical |
| [INV-AUDIT-1](#inv-audit-1) | The audit log is append-only at both the application layer and the database. | Audit | Critical |
| [INV-AUDIT-2](#inv-audit-2) | All user/CI-supplied strings are redacted before reaching audit / errors / notifications. | Audit | Critical |
| [INV-AUDIT-3](#inv-audit-3) | Every governance action is recorded in the audit log. | Audit | High |
| [INV-AUDIT-4](#inv-audit-4) | Web-originated audit entries include IP and User-Agent. | Audit | Medium |
| [INV-AUDIT-5](#inv-audit-5) | Access-log events are retention-bounded (partitioned, droppable) and disjoint from the timeline. | Audit | Medium |
| [INV-AUDIT-6](#inv-audit-6) | A user's first view of an advisory records a durable, never-pruned "receipt" on the ledger. | Audit | Medium |
| [INV-VERSION-3](#inv-version-3) | OSV / CSAF are generated from an immutable `AdvisoryVersion`, never from live data. | Versions | Critical |
| [INV-SECRET-1](#inv-secret-1) | Tokens never appear in `PublicationTask.last_error` or audit metadata. | Secrets | Critical |
| [INV-SECRET-2](#inv-secret-2) | SSH keys and token-bearing URLs are never persisted or logged. | Secrets | Critical |
| [INV-SECRET-3](#inv-secret-3) | Notification bodies are redacted. | Secrets | High |
| [INV-INTAKE-1](#inv-intake-1) | Honeypot trips create `HoneypotSubmission`, never an `Advisory`. | Intake | Critical |
| [INV-INTAKE-2](#inv-intake-2) | The public form has no reporter-email field; anonymous reports cannot be re-associated. | Intake | Critical |
| [INV-INTAKE-3](#inv-intake-3) | Authenticated reporters auto-receive a *viewer* grant on their own report. | Intake | High |
| [INV-INTAKE-4](#inv-intake-4) | Reports filed against the `unsorted` project default to `needs_admin_routing=True`. | Intake | High |
| [INV-RATELIMIT-1](#inv-ratelimit-1) | Rate limits are enforced before the protected operation runs; no side effect on the `429` path. | Rate limit | High |
| [INV-OIDC-1](#inv-oidc-1) | Groups are re-synced from OIDC claims on every login; client group data is never trusted. | Identity | Critical |
| [INV-OIDC-2](#inv-oidc-2) | Authorization always reads from the DB groups mirror, never from request input. | Identity | Critical |
| [INV-OIDC-3](#inv-oidc-3) | `is_staff` / `is_superuser` track admin-group membership on each login. | Identity | High |
| [INV-OIDC-4](#inv-oidc-4) | OIDC group claim values are filtered to SPN form before mirroring. | Identity | Medium |
| [INV-OIDC-5](#inv-oidc-5) | Provisioned (shadow) roster users hold no authorization; roster sync never writes `user.groups`. | Identity | High |
| [INV-OIDC-6](#inv-oidc-6) | An unverified OIDC email is never trusted to create/link an account or redeem invitations. | Identity | High |
| [INV-ROSTER-1](#inv-roster-1) | Shadow roster members get the team's default notifications for their project only, never internal comments; reach is not access. | Notifications | Medium |
| [INV-PUB-1](#inv-pub-1) | Each publication clone uses a fresh `TemporaryDirectory`. | Publication | Critical |
| [INV-PUB-2](#inv-pub-2) | SSH and token authentication are mutually exclusive. | Publication | Medium |
| [INV-PUB-3](#inv-pub-3) | Publication clones are shallow (`depth=1`). | Publication | Medium |
| [INV-PUB-4](#inv-pub-4) | The `state` flip and `PublicationTask` outcome share one transaction. | Publication | Critical |
| [INV-PUB-5](#inv-pub-5) | The Celery task is enqueued via `transaction.on_commit`. | Publication | High |
| [INV-PUB-6](#inv-pub-6) | OSV and CSAF documents are validated against vendored schemas before push. | Publication | High |
| [INV-PUB-7](#inv-pub-7) | Stale queued/running publication tasks are reaped to `failed` without touching advisory state. | Publication | High |
| [INV-PUB-8](#inv-pub-8) | Publication writes never follow a symlink out of the clone tree. | Publication | Medium |
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
| [INV-PROJECT-2](#inv-project-2) | The `unsorted` sentinel project owns all triage filed without a known project. | Projects | High |
| [INV-IMPL-1](#inv-impl-1) | `Advisory.delete()` is blocked at the model layer (and DB trigger). | Structural | Critical |
| [INV-IMPL-2](#inv-impl-2) | `AuditLogEntry.delete()` is blocked. | Structural | Critical |
| [INV-IMPL-3](#inv-impl-3) | `CommentVersion` rows are append-only. | Structural | High |
| [INV-IMPL-4](#inv-impl-4) | Advisory ID generation retries on collision (bounded). | Structural | Medium |
| [INV-IMPL-5](#inv-impl-5) | `AdvisoryVersion` rows are append-only. | Structural | Critical |
| [INV-PRIVACY-1](#inv-privacy-1) | Advisories without access are not enumerable. | Privacy | High |
| [INV-PRIVACY-2](#inv-privacy-2) | Notification recipients are re-checked at send time. | Privacy | High |
| [INV-PRIVACY-3](#inv-privacy-3) | `reporter_display_name` is display-only; never used for authorization. | Privacy | Medium |
| [INV-PRIVACY-4](#inv-privacy-4) | Other users' email addresses are shown only to owners. | Privacy | Medium |
| [INV-GHSA-1](#inv-ghsa-1) | A GHSA-linked advisory's project follows PMI, never a manual edit. | GHSA | High |
| [INV-GHSA-2](#inv-ghsa-2) | Stale queued/running CVE-push tasks are reaped to `failed`, correcting the advisory's CVE-push badge. | GHSA | Medium |
| [INV-GHSA-3](#inv-ghsa-3) | GHSA-linked lifecycle is inbound-only: GitHub publishing auto-publishes; GitHub close/withdraw/delete auto-dismisses (draft/triage) or auto-withdraws (published); AdvisoryHub never writes lifecycle state back to GitHub. | GHSA | Medium |
| [INV-GHSA-4](#inv-ghsa-4) | "Move to GHSA" is the one sanctioned outbound *create* + `kind` flip: a native triage/draft report is authored as a repository advisory on a PVR-enabled repo of its own project and converted in place to GHSA-linked. | GHSA | High |
| [INV-SIM-1](#inv-sim-1) | Duplicate-check results and endpoints are owner-only, enforced server-side. | Similarity | Critical |
| [INV-SIM-2](#inv-sim-2) | `SIMILARITY_CHECK_ENABLED=False` (default) means zero advisory-content egress to the LLM provider. | Similarity | Critical |
| [INV-SIM-3](#inv-sim-3) | LLM provider errors are redacted before persistence; the API key never reaches logs or audit. | Similarity | Critical |
| [INV-SIM-4](#inv-sim-4) | Fingerprint/judge inputs come from the pinned `SimilarityCheck.version` payload, never live data. | Similarity | High |
| [INV-SIM-5](#inv-sim-5) | Stale queued/running similarity checks are reaped to `failed`; the reaper performs no LLM egress. | Similarity | High |
| [INV-CONF-1](#inv-conf-1) | Advisory content is not encrypted at the application layer; content confidentiality at rest is a deployment-layer control and the queried fields stay plaintext. | Confidentiality | High |
| [INV-CONF-2](#inv-conf-2) | Advisory visibility is enforced below the app by Postgres row-level security as a fail-closed backstop; schema-/DB-per-project tenancy is rejected, and the RLS policy is drift-tested against `visible_to`. | Confidentiality | High |

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

**Related.** [INV-PUB-4](#inv-pub-4), [INV-VERSION-3](#inv-version-3),
[INV-PUB-7](#inv-pub-7) (the stale-task reaper also never touches `state`).

---

<a id="inv-lifecycle-4"></a>
### INV-LIFECYCLE-4 — `dismissed` is reversible by owner/admin   [High]

**Statement.** While `state=dismissed`, an advisory cannot be published, edited, or
take CVE workflow actions. Owners and admins may **reopen** a dismissed advisory
via `advisories.services.reopen_advisory`; reopening returns it to its
pre-dismissal state (`triage`, `draft`, recorded in
`Advisory.dismissed_from_state`). A **published** advisory reaches `dismissed`
only by **withdrawal** ([INV-WITHDRAW](#inv-withdraw)) — which re-exports the
OSV/CSAF marked withdrawn and flips state only after the push, so
`dismissed_from_state` may also be `published`. There is no *direct* (publication-less)
`published → dismissed` or `dismissed → published` transition — both go through the
publication pipeline.

**Rationale.** Dismissals are often the right call (duplicate, not-a-vuln,
out-of-scope) but humans make mistakes and new information surfaces. Reopening
into a non-published working state does not bypass any gate — the review and
publication flows still apply on the way back out. Keeping reopen owner-gated
preserves the audit story: reopen creates an `ADVISORY_REOPENED` row, and the
prior `ADVISORY_DISMISSED` plus `dismissed_reason` stay visible as historical
context.

The two dismiss *services* also tear down any pending review state at
dismissal time (`workflows.services.cancel_pending_review` runs from both
`dismiss_triage` and `dismiss_advisory`), so an advisory dismissed from
`triage` or `draft` reopens with `review_status=NONE` and no `OPEN`
`ReviewTask`. This closes the "surviving APPROVED" loophole that would
otherwise let an owner publish on a reopened advisory without a fresh
review ([INV-PERM-3](#inv-perm-3)). A **withdrawal** is the deliberate
exception: the withdrawal branch of `publication.tasks.run_publication`
flips the row to `dismissed` without running the teardown, so a withdrawn
advisory *retains* the `review_status` it held at publication (typically
`approved`; never `submitted` — `can_submit_for_review` requires `draft`).
That is safe because the only route out of a withdrawal is un-withdraw →
re-publication through the pipeline (never an editable working state) —
but it means `dismissed` does **not** blanket-imply `review_status=none`:
a DB constraint of that shape would break every withdrawal.

**Enforced in.**
- `advisories/permissions.py` — `can_reopen` requires `state=dismissed` and
  owner rank. `can_publish`, `can_submit_for_review`, `can_request_cve`, and
  `can_edit` still reject `state=dismissed` (no in-state editing).
- `advisories/services.py::reopen_advisory` — re-checks permission, locks the
  row, and flips state to `Advisory.dismissed_from_state`. CVE side-effects
  (orphan reattachment, cancelled-request restoration) are orchestrated
  through `workflows.services`; see [INV-CVE-3](#inv-cve-3).
- `advisories/services.py::dismiss_triage` and
  `advisories/services.py::dismiss_advisory` (the reusable core behind the
  `advisory_dismiss` view and the GHSA auto-dismiss) — call
  `workflows.services.cancel_pending_review` so advisories dismissed from
  `triage`/`draft` carry `review_status=NONE` and no `OPEN` `ReviewTask`.
  The withdrawal branch of `publication/tasks.py::run_publication`
  intentionally does not run the teardown (see Rationale).

**Violation impact.** Without `can_reopen` gating, a non-owner could revive
suppressed content. Without re-checking state in `reopen_advisory`, a stale
form could push a non-dismissed advisory into an unexpected target state.

**Tests.**
- `advisories/tests/test_reopen.py` — service, permission, view, and orphan
  dispositions.
- `advisories/tests/test_permissions.py` — `can_publish` / `can_edit` still
  reject dismissed.
- `publication/tests/test_pipeline.py` — `test_withdrawal_retains_review_status`
  pins the withdrawal exception (approval retained; `dismissed` does not
  blanket-imply `review_status=none`).

**Related.** [INV-LIFECYCLE-1](#inv-lifecycle-1), [INV-AUTH-1](#inv-auth-1),
[INV-WITHDRAW](#inv-withdraw).

---

<a id="inv-withdraw"></a>
### INV-WITHDRAW — A published advisory is withdrawn, never deleted   [High]

**Statement.** A published advisory may be **withdrawn**: the OSV/CSAF documents
stay in the publication repo (consumers must keep resolving the id) but are
**re-exported with a withdrawn marker** — OSV's `withdrawn` timestamp and a CSAF
withdrawal `revision_history` entry + document note — and the advisory flips to
`dismissed` (`dismissed_from_state=published`). It is driven by
`Advisory.withdrawn_reason`: setting it appends an `AdvisoryVersion`
([INV-VERSION-1](#inv-version-1)), and `publication.tasks.run_publication` keys the
end state off the pinned version — `dismissed` when `withdrawn_reason` is set, else
`published`. State flips **only after the push** ([INV-LIFECYCLE-3](#inv-lifecycle-3)):
a failed withdrawal leaves the advisory `published` with `withdrawn_reason` still set
and a failed `PublicationTask`, and is **retryable** — re-running the withdrawal
(the advisory page's "Retry withdrawal" action, or the admin Publication page) starts
a fresh run that completes it, since the failed task doesn't block the in-flight guard
and `withdrawn_reason` is sticky on the pinned version. A stuck queued/running task is
recovered to `failed` by the [INV-PUB-7](#inv-pub-7) reaper. Any assigned CVE is
orphaned for cve.org rejection (a DB-side `OrphanCve` an admin later marks rejected — that
flow is unchanged), and its on-disk record is **re-exported as a `REJECTED` CVE 5.x record**
(`cveMetadata.state=REJECTED`, `containers.cna.rejectedReasons`=the withdrawal reason) in the
same push, so the publication repo — a mirror of cve.org — reflects the rejection instead of
a stale `PUBLISHED` record.

**Authorization.** A global admin, or a **mature-publisher** project owner
(`can_withdraw_published` — admin OR `is_mature_publisher_member`), may withdraw
directly, even with an assigned CVE (the orphan cascade runs un-gated because the
withdrawal itself was authorized). A non-mature owner cannot withdraw directly.

**Reversible (un-withdraw).** A withdrawn advisory (`dismissed_from_state=published`)
can be reopened back to `published` via `reopen_advisory`: it clears
`withdrawn_reason`, reattaches the orphaned CVE (the existing reopen orphan
disposition), and re-publishes — the export drops the withdrawn marker, the
reattached CVE's record is re-exported `PUBLISHED` again, and the state returns
to `published` after the push (`publish(allow_from_dismissed=True)`). (If the
orphan was already `MARKED_REJECTED`, reopen queues an admin reassignment task
instead of reattaching, so the CVE record correctly stays `REJECTED` until that
is resolved.)
Reopening a withdrawal needs publish authority (admin or mature-publisher owner),
not the plain-owner gate that a draft/triage-origin reopen uses — see
[INV-LIFECYCLE-4](#inv-lifecycle-4).

**Rationale.** OSV/CSAF consumers cache and resolve advisory ids; deleting a record
breaks them. OSV models exactly this with its first-class `withdrawn` field —
"this record is no longer valid, but the id still resolves." Driving the export +
end state off `withdrawn_reason` reuses the whole publication pipeline (build →
validate → push → atomic finalise) and its failure handling, instead of a parallel
path.

**Enforced in.**
- `advisories/permissions.py` — `can_withdraw_published`.
- `advisories/services.py` — `withdraw_advisory` (sets `withdrawn_reason`, appends a
  version, runs the pipeline via `publish(system=True)`).
- `publication/tasks.py` — `run_publication` end-state branch, the withdrawal
  cascade (orphan CVE via `workflows.services.orphan_cve`), and the CVE-build
  branch that emits a REJECTED record on withdrawal.
- `publication/osv.py` / `publication/csaf.py` — withdrawn rendering.
- `publication/cve.py` — `build_rejected_cve` (the `REJECTED` record on withdrawal).
- `advisories/services.py::reopen_advisory` + `advisories.permissions.can_reopen`
  + `publication.services.publish(allow_from_dismissed=True)` — the un-withdraw path.
- `advisories/services.py` — `request_withdrawal` / `cancel_withdrawal_request` /
  `clear_withdrawal_request_if_pending`, gated by `can_request_withdrawal` /
  `can_cancel_withdrawal_request` / `can_approve_withdrawal`. A non-mature owner's
  request (the `withdrawal_requested_*` fields) is surfaced in the Admin Console
  Inbox; an admin approves it (withdraws using the request note) and the request
  clears, or the requester/admin cancels it.

**Violation impact.** A withdrawn advisory keeps masquerading as live in the public
feed, or a published record is deleted and breaks downstream consumers.

**Tests.** `publication/tests/test_pipeline.py` (`test_withdraw_published_advisory`,
`test_unwithdraw_reopens_to_published`), `publication/tests/test_cve.py`
(`build_rejected_cve`), `advisories/tests/test_permissions.py`,
`advisories/tests/test_views.py`.

**Related.** [INV-LIFECYCLE-3](#inv-lifecycle-3), [INV-LIFECYCLE-4](#inv-lifecycle-4),
[INV-VERSION-1](#inv-version-1), [INV-VERSION-3](#inv-version-3).

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

**Statement.** A non-admin edit to an advisory that holds `review_status=approved`
resets `review_status` to `none`; an admin's own edit leaves the approval standing
(admins retract explicitly via `can_revoke_approval`). This applies to **native**
advisories only — GHSA-linked advisories carry no review at all (review is removed for
them; their content is synced from GitHub, [INV-GHSA-1](#inv-ghsa-1)), so a GHSA sync
never touches `review_status`; it only sets `republish_required=True` when changed
content lands on a published advisory.

**Rationale.** An approved review covers a specific content version; substantive
edits invalidate that approval and must be re-reviewed or, for mature publishers,
deliberately re-published. GHSA-linked content isn't human-editable, so there is no
review to invalidate.

**Enforced in.**
- `advisories/views.py` — `advisory_edit` resets `review_status` for non-admin
  editors and sets `republish_required` on published rows.
- `ghsa/services.py` — the sync path sets `republish_required` when content changed
  on a published advisory; it does **not** touch `review_status` (GHSA-linked have no
  review).

**Violation impact.** Publication of an unreviewed change; CSAF/OSV diverging from
what was approved.

**Tests.** `advisories/tests/test_views.py`
(`test_edit_by_owner_invalidates_approval`, `test_edit_by_admin_preserves_approval`,
`test_published_edit_by_owner_invalidates_and_flags_republish`),
`workflows/tests.py`.

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
`api/tests/test_access.py`,
`advisories/tests/test_authz_error_disclosure.py` (validation-error re-render
paths re-check authorization before disclosing advisory content).

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
admins can edit or triage the advisory. Project owners may *flag* a misrouted
advisory (admins cannot — their queue is the destination) and may also *clear*
the flag, retracting their own handoff; while the flag stands, every other
mutation is admin-only. In-place clearing applies only to advisories on a **real**
project — an advisory on the `unsorted` sentinel can be unflagged solely by
reassigning it off `unsorted` ([INV-INTAKE-4](#inv-intake-4)).

**Rationale.** Misrouted reports must reach an admin for re-routing without the
row being mutated underneath them. Flagging is a voluntary handoff: letting the
flagging team unflag gives it no suppression power it didn't already have (it
could have dismissed instead of flagging), and both directions are audited.

**Enforced in.**
- `advisories/permissions.py` — `can_edit`, `can_triage`,
  `can_flag_for_admin_routing`, `can_clear_admin_routing_flag`.

**Violation impact.** Misrouted reports get suppressed by the wrong team.

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

<a id="inv-auth-8"></a>
### INV-AUTH-8 — A banned account is denied login and dropped mid-session   [High]

**Statement.** An admin can ban a user from the admin console. A banned account
(`is_active=False`, with `banned_at`/`banned_by`/`ban_reason` set) cannot complete a
new sign-in *and* loses any live session on its very next request; it also stops
receiving notifications. Banning requires a reason; an admin may ban anyone except
themselves (banning another global admin is an allowed emergency override). `is_active`
is the single enforcement switch and is toggled **only** by `accounts.services.ban_user`
/ `unban_user`. A ban is reversible (`unban`) and both ends are recorded in the durable
audit ledger.

**Rationale.** Group membership is IdP-mediated and only re-syncs at login
([INV-OIDC-3](#inv-oidc-3)), so revoking access by changing a group does not end a
live session or take effect until next login. A ban is the one app-side override that
acts immediately, for a compromised or abusive account, without waiting on the IdP.
The append-only audit trail keeps the who/when/why for forensics.

**Enforced in.**
- `accounts/services.py` — `ban_user` / `unban_user` set the metadata and flip
  `is_active` in lockstep.
- `accounts/auth.py` — `AdvisoryHubOIDCBackend.get_user` returns `None` for an inactive
  user (restoring the `is_active` check mozilla-django-oidc's `get_user` drops), so
  `AuthenticationMiddleware` resolves a banned user to `AnonymousUser` next request. New
  logins are refused by the OIDC callback view's own `is_active` gate.
- `admin_console/views/users.py` — `user_ban` / `user_unban` (`@admin_required`,
  `@require_POST`, self-ban guard, required reason) record the durable
  `Action.USER_BANNED` / `USER_UNBANNED` entries via `record_from_request`.
- `notifications/recipients.py`, `notifications/tasks.py` — already filter
  `is_active=True`, so a banned user drops out of recipient resolution.

**Violation impact.** A compromised or abusive account keeps an authenticated session
(or signs back in) after an admin has revoked it; or a ban leaves no audit trail.

**Residual.** A Celery task already queued under a now-banned actor re-checks
group-based authorization (not `is_active`), matching IdP-demotion semantics; it is not
retro-blocked by the ban.

**Tests.** `accounts/test_ban.py`, `admin_console/test_ban.py`.

**Related.** [INV-OIDC-3](#inv-oidc-3), [INV-AUTH-1](#inv-auth-1), [INV-AUDIT-1](#inv-audit-1).

---

<a id="inv-auth-9"></a>
### INV-AUTH-9 — Draft admin-reassignment requests are non-locking   [High]

**Statement.** A project owner who finds a **draft** advisory belongs to a team they're
not on may ask an admin to re-home it (`request_admin_reassignment`). Unlike the triage
routing flag ([INV-AUTH-6](#inv-auth-6)), a pending request does **not** strip the
team's edit/publish capability — work continues while the request sits in the queue.
Global admins cannot *request* (they reassign directly); only one request is pending at
a time; requests exist only in `draft`. The request applies to **native** drafts only — a
GHSA-linked draft's project follows PMI ([INV-GHSA-1](#inv-ghsa-1)) and is never hand-reassigned,
so `can_request_reassignment` is always false for it. An optional **suggested target project** (never
the advisory's current project) enables a one-click accept by a global admin **or** a
security-team member of that target project — but never by the requester (who is on the
current team, not the target). A **global admin** may also resolve the request by
reassigning to **any** project of their choice (an in-banner picker), not only the
suggestion — sparing them the full edit form. Either way the move onto the target appends
an `AdvisoryVersion` (`project_slug` is payload-visible), flags an access review, clears
the request, and is audited. The request is cleared — clearing all four `reassignment_*`
fields — on withdraw (requester or admin), accept/reassign, **any project change made
through the edit form** (which fulfils the request the same way — cleared with cause
`accepted`), or **any exit from draft** (dismiss / publish). Every transition is audited.

**Rationale.** The draft analogue of the triage routing flag, but draft work is trusted
and collaborative, so a misrouting hint must not freeze the team the way an untrusted
triage row is frozen. The suggestion + scoped accept lets the *receiving* team (or an
admin) pull the advisory over without handing the requester cross-team authority they
don't have (owner is derived — [INV-AUTH-3](#inv-auth-3)).

**Enforced in.**
- `advisories/permissions.py` — `can_request_reassignment`, `can_withdraw_reassignment_request`,
  `can_accept_reassignment_suggestion`, `can_pick_reassignment_target`, `can_resolve_reassignment`.
- `advisories/services.py` — `request_admin_reassignment`, `withdraw_admin_reassignment`,
  `accept_reassignment_suggestion`, and the shared `clear_reassignment_request_if_pending`.
- Auto-clear on draft exit: `advisories/views.py` `advisory_dismiss` and
  `publication/tasks.py` (post-push finalisation).

**Violation impact.** A misrouting hint silently locks a trusted team out of its own
draft, or a requester gains the ability to move advisories onto teams they're not on.

**Tests.** `advisories/tests/test_draft_reassignment.py`.

**Related.** [INV-AUTH-6](#inv-auth-6), [INV-AUTH-3](#inv-auth-3), [INV-VERSION-1](#inv-version-1).

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
  still received (and recorded) rather than dropped.
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
removal would itself appear in `git log`. The sole sanctioned removal path —
`prune_audit`'s controlled bypass (`audit/retention.py`) — records each sweep as
an `AUDIT_PRUNED` ledger entry in the same transaction, so even retention itself
stays in the history.

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
attempts (success and failure), OIDC group sync changes, intake transitions,
site-wide maintenance toggles, project create / edit (the security-team group
binding confers owner rank), and the first-view compliance receipt
(`advisory.first_seen`, emitted once per user per advisory — see
[INV-AUDIT-6](#inv-audit-6)).

**Rationale.** Compliance and forensics rely on a complete record. Missing entries
make incident investigation guesswork.

**Enforced in.**
- `audit/models.py` — `Action` enum enumerates every recordable action.
- Each service module emits its corresponding `Action` (advisories, access,
  comments, workflows, publication, intake, accounts, projects).

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

**Statement.** The actions in `audit.models.EPHEMERAL_ACTIONS` (advisory views,
GHSA/PMI machine chatter, authentication events — `auth.login` / `auth.logout` /
`auth.login_failed` / `auth.step_up_completed` — and per-recipient notification
deliveries `notification.sent`) are written to `AccessLogEntry`, **not** the
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

**First-view receipt.** `advisory.viewed` is ephemeral (every open, pruned at
90 days), but a user's *first* open additionally emits a durable
`advisory.first_seen` receipt that must survive indefinitely — it therefore
**must stay out of `EPHEMERAL_ACTIONS`** (and out of the timeline tiers). Full
statement in [INV-AUDIT-6](#inv-audit-6).

**Rationale.** View pings, integration chatter, sign-in activity, and
per-recipient notification fan-out dominate audit volume but carry no long-term
compliance value and never appear on a timeline. Isolating them lets the ledger
stay small and fully tamper-proof while this table is pruned cheaply. The source
IPs and recipient emails captured here are PII, so retention pruning +
`forget_user` deletion double as the GDPR control for them.

**Enforced in.**
- `audit/models.py` — `AccessLogEntry`, `EPHEMERAL_ACTIONS`.
- `audit/services.py` — `record()` routes by action.
- `audit/migrations/0003_accesslogentry.py` — partitioned table DDL.
- `audit/partitions.py`, `audit/tasks.py` — partition lifecycle / retention.

**Violation impact.** Either unbounded growth (retention disabled/broken) or, if
the disjointness is violated, silent loss of timeline-visible history.

**Tests.** `audit/tests.py`, `audit/test_partitions.py`,
`advisories/tests/test_access_log_disjoint.py`, `audit/test_retention.py`,
`advisories/tests/test_first_seen_receipt.py`.

**Related.** [INV-AUDIT-1](#inv-audit-1), [INV-AUDIT-2](#inv-audit-2),
[INV-AUDIT-4](#inv-audit-4), [INV-AUDIT-6](#inv-audit-6).

---

<a id="inv-audit-6"></a>
### INV-AUDIT-6 — First-view receipt is durable   [Medium]

**Statement.** The first time a given user opens an advisory's detail page,
exactly one durable `advisory.first_seen` `AuditLogEntry` is recorded — an
implicit "acknowledgment of receipt" proving the user was made aware. It is
emitted once per `(user, advisory)` and is **never auto-pruned**. The action
**must not** appear in `audit.models.EPHEMERAL_ACTIONS` (it would then be
partition-dropped, [INV-AUDIT-5](#inv-audit-5)) nor in any `advisories.timeline`
tier (it is admin-queryable on the audit log, not per-event timeline noise). The
every-open `advisory.viewed` access-log row is retained alongside it for
short-term telemetry.

**Mechanism & PII.** First-view detection reuses the
`AdvisoryVisit.update_or_create` `created` flag in
`advisories.views.advisory_detail` (`created is True` ⟺ first-ever open;
`update_or_create`'s IntegrityError-retry makes that race-safe). The receipt is
written via `audit.services.record` — **not** `record_from_request` — so it
carries no IP/User-Agent: the never-pruned row holds no PII beyond the actor FK,
which `forget_user` pseudonymises (the row survives, identity degrades to
"user #N (forgotten) saw advisory X at time T"). Uniqueness rides on the
`AdvisoryVisit` row; nothing clears it for an active user today, and a re-emitted
receipt would be a harmless append-only duplicate (the compliance answer is
unchanged).

**Rationale.** Compliance needs durable evidence that a user became aware of an
advisory, but every-view telemetry is high-volume PII intentionally pruned at
90 days ([INV-AUDIT-5](#inv-audit-5)). Splitting the *first* view onto the
durable ledger keeps the compliance record while the access log stays cheap and
erasure-friendly.

**Enforced in.**
- `advisories/views.py` — `advisory_detail` emits the receipt on the first visit.
- `audit/models.py` — `Action.ADVISORY_FIRST_SEEN`, deliberately kept out of
  `EPHEMERAL_ACTIONS`.
- `advisories/timeline.py` — absent from every tier, so it lands in
  `EXCLUDED_ACTIONS`.

**Violation impact.** If the action were made ephemeral, the compliance receipt
would be silently pruned after the retention horizon; if recorded with IP/UA,
the never-pruned ledger would accumulate un-erasable PII.

**Tests.** `advisories/tests/test_first_seen_receipt.py`,
`advisories/tests/test_access_log_disjoint.py`.

**Related.** [INV-AUDIT-1](#inv-audit-1), [INV-AUDIT-3](#inv-audit-3),
[INV-AUDIT-5](#inv-audit-5).

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
- `advisories/views.py` — `advisory_edit` calls `record_advisory_version` with
  `if_changed=True` after a successful form save, so a save that changes no
  payload-visible field appends nothing (native advisories only; GHSA-linked
  advisories are not editable here — see [INV-GHSA-1](#inv-ghsa-1)).
- `ghsa/services.py` — `sync_single_ghsa` appends a version only when
  `result.changed_field_names` is non-empty (filters out heartbeat syncs);
  `sync_project_repos_from_pmi` appends one when a PMI re-home moves a GHSA-linked
  advisory to a different project (`project_slug` is payload-visible).

**Violation impact.** Editorial history either has gaps (missing rows for real
edits) or noise (rows for non-content saves), in either case losing its value
for review and audit.

**Tests.** `advisories/tests/test_versions.py`,
`advisories/tests/test_models.py`, `advisories/tests/test_views.py`
(`test_edit_with_unchanged_payload_appends_no_version`).

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
duration of a `publish_files` call. SSH identity wiring exists only as a per-call
`GIT_SSH` wrapper script inside the call's private scratch `TemporaryDirectory`,
passed via a per-call environment dict (the global `os.environ` is never
mutated), and is deleted with the scratch directory. Neither is written to any
model.

**Rationale.** Even in-memory exposure has to be bounded; persistence makes a
single forensic dump catastrophic.

**Enforced in.**
- `publication/git_service.py` — `_embed_token` is transient; `_write_ssh_wrapper`
  writes into the per-call scratch dir and `_git_env` builds a per-call env dict.

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
automatically set `AdvisoryIntakeMetadata.needs_admin_routing=True`. The coupling
is two-directional and holds for the whole time an advisory sits on `unsorted`
in triage: while on `unsorted`, the flag may **not** be cleared in place — it is
lifted only by moving the advisory *off* `unsorted` (reassign to a real project,
promote, or dismiss); conversely, reassigning an advisory *onto* `unsorted`
(re)sets the flag. An `unsorted` triage advisory with `needs_admin_routing=False`
is an invalid limbo state.

**Rationale.** When the reporter does not know the right project, the report must
land with admins for re-routing, not in some default team's queue. The flag *is*
the routing signal; allowing it to be cleared while the advisory stays on
`unsorted` would strand the report on the routing-bucket project with nothing
flagging it for routing. Clearing in place stays valid only on a **real** project
(a team retracting its own misrouting handoff, [INV-AUTH-6](#inv-auth-6)).

**Enforced in.**
- `advisories/services.py` — `submit_triage_report` sets the flag when
  `project.slug == UNSORTED_PROJECT_SLUG`; `reassign_triage_project` (re)sets the
  flag when the destination is `unsorted` and clears it only when re-routing to a
  real project.
- `advisories/permissions.py` — `UNSORTED_PROJECT_SLUG`;
  `can_clear_admin_routing_flag` rejects clearing while on `unsorted`.

**Violation impact.** Misrouted reports get suppressed by the wrong team.

**Tests.** `advisories/tests/test_triage.py`.

**Related.** [INV-AUTH-6](#inv-auth-6), [INV-PROJECT-2](#inv-project-2).

---

<a id="inv-ratelimit-1"></a>
### INV-RATELIMIT-1 — Rate limits are enforced before the protected operation   [High]

**Statement.** A rate-limited view's side effects — DB writes, outbound email,
LLM / GitHub-API calls, Git pushes — never run on a throttled request. The limit
is evaluated (and counted) and the `429` returned **before** the wrapped view is
invoked, not after it has already run.

**Rationale.** A limit checked *after* the view runs is cosmetic: the side effect
has already happened and swapping in a `429` only changes the response body,
actively misleading log-based abuse monitoring into reporting the cap as
"working". The anonymous intake limit (`RATELIMIT_INTAKE_ANON`) is the only
quantitative cap on the sole unauthenticated mutating endpoint
([INV-INTAKE-1](#inv-intake-1)), so its enforcement timing is load-bearing.

**Enforced in.**
- `common/ratelimit.py` — `html_ratelimit` / `json_ratelimit` call
  `is_ratelimited(..., increment=True)` and short-circuit with the `429` body
  *before* dispatching to the view.
- `intake/views.py` — `_handle_post` checks the limit before `_do_submit`.

**Violation impact.** Unbounded `Advisory(state=triage)` creation plus one triage
email per project-security-team member from anonymous clients; unbounded
invitation email, LLM cost, GitHub-API fan-out, and Git pushes from users who
already hold the relevant role.

**Tests.** `common/tests.py`, `intake/tests/test_views_public.py`.

**Related.** [INV-INTAKE-1](#inv-intake-1), [INV-LIFECYCLE-2](#inv-lifecycle-2).

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

**Rationale.** These Django flags must follow IdP demotion without manual
intervention. They gate nothing in-app today — Django's built-in admin is not
mounted and the admin console keys off group membership — so the sync is
defense-in-depth hygiene: it keeps the columns honest (e.g. against any future
re-introduction of an `is_staff`-gated surface) rather than leaving a stale
super-user flag set after a demotion.

**Enforced in.**
- `accounts/auth.py` — `_apply_claims`.

**Violation impact.** A demoted admin keeps `is_staff` / `is_superuser` set,
re-arming any flag-gated surface that is later added.

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

> A shadow user is `is_active=True` (so it stays a notification recipient). Banning
> one ([INV-AUTH-8](#inv-auth-8)) flips it to `is_active=False`, which also removes it
> from notification recipient resolution — the same `is_active` filter applies.

**Tests.** `projects/test_roster_sync.py`, `accounts/test_roster_linking.py`.

**Related.** [INV-OIDC-1](#inv-oidc-1), [INV-AUTH-3](#inv-auth-3),
[INV-ROSTER-1](#inv-roster-1).

---

<a id="inv-oidc-6"></a>
### INV-OIDC-6 — Unverified OIDC email is never trusted to establish identity   [High]

**Statement.** The OIDC `email` claim is trusted to identify a user — to link to
an existing account (the email *fallback* in
`AdvisoryHubOIDCBackend.filter_users_by_claims`), to create a new one
(`create_user`), to be written onto a `User` (`_apply_claims`), and thereby to
redeem `PendingInvitation`s addressed to that address — **only when**
`_email_is_verified(claims)` holds. The stable `sub` match is authoritative and
unaffected. When the OP marks the email unverified, the email fallback returns no
user and account creation is **refused** (`SuspiciousOperation`, caught by the
library's `authenticate` and routed to the audited `login_failure`): no `User`
row is created, the unique address is not squatted, and no invitation is
redeemed. An *explicit* falsey `email_verified` (`false`, `"false"`, `null`)
always blocks. The **absent** case follows `OIDC_REQUIRE_EMAIL_VERIFIED`
(default `False` → trusted, because our single configured OP, Kanidm, omits the
claim); set it `True` for an OP that allows unverified-email signup or federates
an upstream that forwards `email` without re-verification.

**Rationale.** AdvisoryHub is admin-provisioned and invitation-based; an
unverified email is an attacker-controllable identity assertion. Trusting it on
the create path let an attacker holding an OP token for a victim's email redeem
any outstanding invitation to that address — gaining viewer/collaborator access
to an embargoed advisory — and permanently squat the unique email
([INV-ACCESS-2](#inv-access-2)). The fallback gate alone (the earlier "S2" fix)
covered only account *linking*; this invariant makes the rule uniform across
linking, creation, and the email-write.

**Enforced in.**
- `accounts/auth.py` — `_email_is_verified` (the gate; honors
  `OIDC_REQUIRE_EMAIL_VERIFIED`), `filter_users_by_claims` (link fallback),
  `create_user` (refuses on unverified), `_apply_claims` (email-write guard).

**Violation impact.** An attacker who can obtain an OP token carrying a victim's
unverified email claims any pending invitation to that address and permanently
squats the unique `User.email`.

**Tests.** `accounts/test_email_linking.py`.

**Related.** [INV-OIDC-1](#inv-oidc-1), [INV-ACCESS-2](#inv-access-2),
[INV-AUTH-1](#inv-auth-1).

---

<a id="inv-roster-1"></a>
### INV-ROSTER-1 — Roster notification reach is default-set, per-project, never internal   [Medium]

**Statement.** Active roster shadow members of a project
(`SecurityTeamRosterEntry`, `soft_removed_at IS NULL`, linked user
`is_provisioned=True`) are eligible notification recipients **only for their own
project's advisories**, with the *default*-preference set of a security-team member
— `advisory_created`, the lifecycle events, the project-team **triage events**
(submitted/promoted/dismissed/reassigned/reopened; gated by
`NotificationPreference.on_triage_event`), and `@`-mentions (including a `@team`
mention of the project's security group). They are always dropped from **internal**
comments by the `can_see_internal_comment` floor, and (with default preferences) do
not receive every ordinary comment. The admins-only routing-flag event is never
sent to shadows (they are project-team members, not admins). Roster membership
authorizes only this email channel; it confers no in-app view/owner access
([INV-OIDC-5](#inv-oidc-5)).

**Rationale.** Reaching the full security team — including members who have never
logged in — is the whole point of the roster ([INV-OIDC-5](#inv-oidc-5)). The
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

<a id="inv-pub-7"></a>
### INV-PUB-7 — Stale publication tasks are bounded   [High]

**Statement.** A beat-scheduled reaper (`publication.reap_stale_publication_tasks`,
every 10 minutes) flips `PublicationTask` rows stuck in `running` past
`PUB_TASK_STALE_RUNNING_AFTER_SECONDS` (default 1800 s, measured from
`started_at`) or in `queued` past `PUB_TASK_STALE_QUEUED_AFTER_SECONDS`
(default 7200 s, measured from `created_at`) to `failed`, never modifying
`Advisory.state`. Each reap is a per-row compare-and-set under
`select_for_update(skip_locked=True)`: a row finalised concurrently falls out
of the status filter and is skipped, never clobbered.

**Rationale.** A worker hard-killed mid-run (hard `time_limit` SIGKILL, OOM
kill, pod eviction) leaves a row in `running` that the redelivered message
no-ops against (the entry guard accepts only queued/failed); a broker outage
swallowed by `safe_enqueue` leaves a `queued` row with no message at all.
Either row makes the [INV-CONCURRENCY-1](#inv-concurrency-1) in-flight guard
block `publish()` forever, and the admin Retry path accepts `failed` only —
the advisory becomes permanently unpublishable. The thresholds sit above the
physical constants they are anchored to (the 660 s hard `time_limit`; the
3600 s broker `visibility_timeout`), so the reaper can never race a live
execution or a pending redelivery.

**Enforced in.**
- `publication/services.py` — `reap_stale_tasks` / `_reap_one`.
- `publication/tasks.py` — `reap_stale_publication_tasks`.
- `config/settings/base.py` — `CELERY_BEAT_SCHEDULE["publication-task-reaper"]`,
  `PUB_TASK_STALE_*` knobs.

**Violation impact.** An advisory blocked from publishing indefinitely, with
no recovery short of manual SQL.

**Tests.** `publication/tests/test_reaper.py`.

**Related.** [INV-CONCURRENCY-1](#inv-concurrency-1),
[INV-LIFECYCLE-3](#inv-lifecycle-3), [INV-PUB-4](#inv-pub-4),
[INV-SECRET-1](#inv-secret-1), [INV-SIM-5](#inv-sim-5) and
[INV-GHSA-2](#inv-ghsa-2) (the similarity and GHSA mirrors of this rule).

---

<a id="inv-pub-8"></a>
### INV-PUB-8 — Publication writes stay inside the clone tree   [Medium]

**Statement.** A publication run never follows a symlink out of its clone. The
clone is taken with `core.symlinks=false` so a symlink committed at the
publication repo's HEAD is materialised as a plain file (never a real link), and
`_write_files` additionally refuses any write whose `resolve()`-d target is not
relative to the clone root (raising `GitPublicationError`).

**Rationale.** The checked-out tree is whatever the publication repo's HEAD
contains, and its committer set is governed by the Git host's permissions — a
plausibly lower-trust principal than the Celery worker (which holds the DB
credentials, OIDC client secret, and deploy key). `Path.write_text` follows
symlinks by default, so without these guards a committer could plant a symlink at
a deterministic write path (e.g. `osv/<year>/<advisory-id>.json`) and redirect
the next publish's write outside the clone (CWE-59) — corrupting `/tmp` files
under the chart's `readOnlyRootFilesystem`, or application code on a non-hardened
deployment. The two layers are independent: the clone flag is the root-cause
fix, the containment assertion also covers a `..` path or any future caller.
In-tree symlinks are not an escape and are left alone — a committer who can push
already controls the whole tree.

**Enforced in.**
- `publication/git_service.py` — `publish_files` (`-c core.symlinks=false` on
  clone), `_write_files` (resolved-target containment check).

**Violation impact.** Out-of-tree file overwrite by a publication-repo committer:
DoS of subsequent publications (corrupting the entrypoint's nss_wrapper files) or
arbitrary file overwrite / code execution on a writable rootfs.

**Tests.** `publication/tests/test_git_service.py`
(`test_publish_does_not_follow_symlink_out_of_tree`,
`test_write_files_refuses_symlink_escape`).

**Related.** [INV-PUB-1](#inv-pub-1), [INV-PUB-3](#inv-pub-3),
[INV-SECRET-2](#inv-secret-2).

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

**Related.** [INV-ACCESS-3](#inv-access-3), [INV-OIDC-6](#inv-oidc-6).

---

<a id="inv-access-3"></a>
### INV-ACCESS-3 — Invitations expire   [Medium]

**Statement.** `PendingInvitation` rows carry an expiry (default 14 days). Expired
invitations cannot be redeemed. An admin re-send (`access.services.resend_invitation`,
surfaced on the Admin Console Invitations page) resets `expires_at` to a fresh
default window — the deliberate, audited way to make a lapsed link usable again.

**Rationale.** Limits the window during which a leaked invitation token is
useful.

**Enforced in.**
- `access/models.py` — `PendingInvitation` with `is_expired` predicate.
- `access/services.py` — redemption checks `is_expired`; `resend_invitation`
  refreshes the window via the same `_default_invitation_expiry` default.

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
create / redeem / revoke / resend emits an audit entry.

**Rationale.** Access changes are the most sensitive non-state-machine action;
the audit trail must answer "who gave whom access to what, when?"

**Enforced in.**
- `access/services.py` — emits `ACCESS_GRANTED` / `ACCESS_REVOKED` /
  `INVITATION_*` actions (including `INVITATION_RESENT` on admin re-send).

**Violation impact.** Silent access changes; broken forensic record.

**Tests.** `access/tests.py`, `audit/tests.py`, `admin_console/test_invitations.py`.

**Related.** [INV-AUDIT-3](#inv-audit-3).

---

## 12. Comments

<a id="inv-comment-1"></a>
### INV-COMMENT-1 — `is_internal` is set at creation   [High]

**Statement.** `AdvisoryComment.is_internal` is fixed when the comment is created
and is not mutated afterwards.

**Rationale.** Flipping the internal flag after the fact would silently broaden or
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
queued or running `PublicationTask` already exists for the advisory. Under that
same lock it re-evaluates the authorization gates — `can_publish(by, locked)`
(skipped only for `system=True`) and the dismissed-state guard — and pins the
version from the freshly-read `locked` row, never from the caller-supplied
in-memory `advisory`. So a content edit that voids an APPROVED review
(`review_status` → `NONE`) or a concurrent dismiss committed *after* the view
fetched the advisory cannot slip an unreviewed (or dismissed) version into a
publication run.

**Rationale.** Serialises publication attempts so two pushes do not race for the
same path in the publication repo, *and* closes the check-then-act gap (CWE-367)
between the view's read and the lock: `advisory_edit` commits in autocommit (no
`ATOMIC_REQUESTS`), so without the under-lock re-check an owner on a non-mature
project could reuse a prior admin approval to publish unreviewed content
([INV-AUTH-1](#inv-auth-1), [INV-PERM-3](#inv-perm-3)) — the edit-race twin of
the "surviving APPROVED" loophole [INV-LIFECYCLE-4](#inv-lifecycle-4) closes on
reopen. The guard cannot deadlock an advisory permanently: stale queued/running
rows are bounded by the reaper ([INV-PUB-7](#inv-pub-7)).

**Enforced in.**
- `publication/services.py` — `publish` (lock-then-re-check, mirroring the
  locked-row re-check convention in `advisories/services.py`).

**Violation impact.** Lost or out-of-order commits in the publication repo;
unreviewed or dismissed advisory content reaching the public OSV/CSAF feed.

**Tests.** `publication/tests/test_pipeline.py`
(`test_publish_rechecks_review_status_under_lock`,
`test_publish_rechecks_dismissed_state_under_lock`,
`test_publish_allowed_for_non_mature_member_when_approved`).

**Related.** [INV-AUTH-1](#inv-auth-1), [INV-PERM-3](#inv-perm-3),
[INV-LIFECYCLE-4](#inv-lifecycle-4), [INV-PUB-1](#inv-pub-1),
[INV-PUB-4](#inv-pub-4), [INV-PUB-7](#inv-pub-7).

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
- `workflows/services.py` — the ban is set by `transition_cve_request(..., ban_future_requests=True)` (only on a rejection) and cleared by `unban_cve_requests`; both gate on `perms.can_review` (admin-only).
- Admin-console flow — the `admin_console:cve_allow` endpoint (POST), surfaced as the "CVE requests banned" section on the CVE Assignment page (`/admin/cves`), is `@admin_required`.

**Violation impact.** Users escape rejection by spamming requests.

**Tests.** `advisories/tests/test_permissions.py`, `workflows/tests.py` (`test_unban_*`), `admin_console/test_admin_console.py` (`test_cve_allow_*`, `test_cves_page_lists_banned_advisory`).

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

**Related.** [INV-AUTH-7](#inv-auth-7), [INV-CONF-1](#inv-conf-1).

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

<a id="inv-privacy-4"></a>
### INV-PRIVACY-4 — Other users' emails are owner-only   [Medium]

**Statement.** A participant's email address is shown only to **owners** of the
advisory (global admins + the project security team —
`advisories.permissions.can_see_user_emails`). Collaborators and viewers see
display names only; where a user has no display name the email is rendered in a
masked form (`a•••@example.org`, `accounts.utils.mask_email`). A user always
sees their *own* email. This holds on every display surface — rendered pages,
the `@`-mention autocomplete, and the JSON API.

**Rationale.** An email address is PII. Only the people running the advisory
(who manage access and correspond off-platform) need other participants'
addresses; an external grantee or the auto-granted triage reporter does not.
The decision is made server-side (the view/serializer), and the template merely
displays the resulting flag — hiding it in the template alone would not be
security ([INV-AUTH-1](#inv-auth-1)).

**Enforced in.**
- `advisories/permissions.py` — `can_see_user_emails` (owner-only predicate).
- `accounts/templatetags/user_display.py` + `templates/accounts/_user_chip.html`
  — the chip reveals the email/popover only when `viewer_can_see_emails` is set
  (by `common.context_processors.user_email_visibility` for global admins, and
  per-advisory by the advisory-scoped views) or the chip is the viewer's own.
- `comments/services.py` — `mention_candidates` masks labels for non-owners.
- `api/serializers.py` — `comment_to_dict`/`grant_to_dict`/`invitation_to_dict`/
  `cve_task_to_dict`/`review_task_to_dict` take a fail-closed `show_emails` flag
  threaded from the endpoint's existing permission check.

**Violation impact.** PII leak: a low-trust viewer harvests the email addresses
of the security team and other reporters.

**Tests.** `accounts/tests/test_mask_email.py`,
`advisories/tests/test_permissions.py`, `advisories/tests/test_views.py`,
`comments/tests.py`, `api/` comment-endpoint tests.

**Related.** [INV-AUTH-1](#inv-auth-1), [INV-PRIVACY-1](#inv-privacy-1).

---

## 19. GHSA integration

<a id="inv-ghsa-1"></a>
### INV-GHSA-1 — A GHSA-linked advisory's project follows PMI, never a manual edit   [High]

**Statement.** A GHSA-linked advisory's `project` is *derived* from its source
GitHub repository at creation (`ghsa.services.create_ghsa_linked_advisory`, from
the `ProjectGitHubRepository` PMI mirror). It is never editable by a human in
AdvisoryHub: there is no edit form for GHSA-linked advisories, and
`Advisory.clean` rejects any `project` change on a GHSA-linked row. The **only**
sanctioned project change is `ghsa.services.sync_project_repos_from_pmi`
re-homing the advisory when PMI re-maps its repository to a different project;
that path stamps the access-review banner and re-flags `republish_required` when
published. (GHSA-linked advisories carry no AdvisoryHub review — it's removed for
them; their content is vetted upstream on GitHub. See [INV-REVIEW-4](#inv-review-4).)

**Rationale.** PMI (`projects.eclipse.org`) is the source of truth for the
repo↔project mapping. A GHSA-linked advisory bridges a specific repository, so
its owning project must track that repository's PMI ownership — not a human's
hand-assignment. A manual reassignment would drop the advisory into a project
that does not own its repo, and the drift would be permanent and invisible:
`sync_single_ghsa` never overwrites `project`. Removing the manual path and
letting PMI be the sole driver keeps the mapping coherent and self-healing.

**Enforced in.**
- `advisories/models.py` — `Advisory.clean` rejects a `project` change on a
  GHSA-linked advisory. This fires for every ModelForm and Django-admin save;
  the PMI re-home saves via `update_fields` and so deliberately bypasses `clean`.
- `advisories/views.py` — `advisory_edit` raises `PermissionDenied` for
  GHSA-linked advisories (they have no editable fields); the detail sidebar
  hides the Edit button via `can_edit and not is_ghsa_linked`.
- `advisories/permissions.py` — `can_request_reassignment` and
  `can_flag_for_admin_routing` refuse GHSA-linked advisories, so neither the
  draft reassignment-request flow ([INV-AUTH-9](#inv-auth-9)) nor the triage
  routing flag ([INV-AUTH-6](#inv-auth-6)) can become a human path to change
  their project — even though a GHSA-linked row can now sit in `triage` as a
  read-only GitHub mirror ([INV-GHSA-3](#inv-ghsa-3)), its project still follows
  PMI. The single predicate gates the button, the modal, and the service
  re-check alike.
- `ghsa/services.py` — `sync_project_repos_from_pmi` re-homes GHSA-linked
  advisories to follow PMI (`_reassign_ghsa_advisories_following_pmi`), appending
  a version, auditing `ADVISORY_PROJECT_CHANGED` with `reason=pmi_repo_reassignment`,
  and notifying the destination project's security team.

**Violation impact.** A GHSA-linked advisory sits in a project that does not own
its repo; its implicit owners (project security team), notification routing, and
published project name diverge from PMI truth with no reconciliation path.

**Tests.** `advisories/tests/test_models.py`, `advisories/tests/test_views.py`,
`ghsa/tests/test_pmi_reassignment.py`.

**Related.** [INV-ID-2](#inv-id-2), [INV-PROJECT-2](#inv-project-2),
[INV-VERSION-1](#inv-version-1), [INV-AUTH-1](#inv-auth-1),
[INV-REVIEW-4](#inv-review-4).

---

<a id="inv-ghsa-2"></a>
### INV-GHSA-2 — Stale CVE-push tasks are bounded   [Medium]

**Statement.** A beat-scheduled reaper (`ghsa.tasks.reap_stale_cve_push_tasks`,
every 10 minutes) flips `GhsaCvePushTask` rows stuck in `running` past
`GHSA_CVE_PUSH_STALE_RUNNING_AFTER_SECONDS` (default 1800 s, measured from
`started_at`) or in `queued` past `GHSA_CVE_PUSH_STALE_QUEUED_AFTER_SECONDS`
(default 7200 s, measured from `created_at`) to `failed`, via the same per-row
compare-and-set under `select_for_update(skip_locked=True)` as
[INV-PUB-7](#inv-pub-7) / [INV-SIM-5](#inv-sim-5). The advisory's CVE-push
badge is corrected with a guard: `ghsa_cve_push_status` flips
`pending → failed` (stamping `ghsa_cve_push_attempted_at`) only while it
still reads `pending` **and** no other queued/running push task exists for
the advisory — the badge is advisory-scoped and overwritten by every new
enqueue, so it may belong to a newer task. Conflict fields are never touched.
The reaper is DB-only (no GitHub egress) and runs even while
`GHSA_FEATURE_ENABLED` is off. `GhsaSyncRun` is deliberately not covered: its
creators are `transaction.atomic`, so the `running` row commits only together
with its finalisation — an interrupted run rolls back instead of stranding.

**Rationale.** `run_cve_push` is a plain task without `acks_late`: the broker
message is acked at pickup, so a worker hard-killed mid-push leaves the row
`running` with no redelivery — and the GHSA panel shows the advisory's
CVE-push status as "Pending" forever. A broker outage swallowed by
`safe_enqueue` strands `queued` rows the same way. Unlike
[INV-PUB-7](#inv-pub-7)/[INV-SIM-5](#inv-sim-5)
nothing *blocks* (there is no in-flight guard, multiple push tasks may
coexist) — this is display truth, hence Medium. A `running` row older than
the threshold cannot belong to a live attempt: a push is one GitHub API call
bounded by the client's connect/read timeouts (10 s/30 s).

**Enforced in.**
- `ghsa/services.py` — `reap_stale_cve_push_tasks` / `_reap_one_push`;
  `sync_ghsas_for_project` / `sync_ghsas_for_all_projects` (the load-bearing
  `transaction.atomic` that exempts `GhsaSyncRun`).
- `ghsa/tasks.py` — `reap_stale_cve_push_tasks`.
- `config/settings/base.py` — `CELERY_BEAT_SCHEDULE["ghsa-cve-push-reaper"]`,
  `GHSA_CVE_PUSH_STALE_*` knobs.

**Violation impact.** Operators misled: a dead push reads as in-flight on the
advisory's GHSA panel indefinitely. No functional block.

**Tests.** `ghsa/tests/test_reaper.py`.

**Related.** [INV-PUB-7](#inv-pub-7), [INV-SIM-5](#inv-sim-5),
[INV-GHSA-1](#inv-ghsa-1).

---

<a id="inv-ghsa-3"></a>
### INV-GHSA-3 — GHSA-linked lifecycle is inbound-only   [Medium]

**Statement.** A GHSA-linked advisory's lifecycle is **inbound-only**: GitHub is
the source of truth and AdvisoryHub *mirrors* it, never writing lifecycle state
back to GitHub. There are exactly two outbound writes, and both *establish or
annotate* the link rather than drive an existing GHSA's lifecycle: the
EF-assigned CVE-id push ([INV-GHSA-2](#inv-ghsa-2)), and the one-time **Move to
GHSA** create that authors the repository advisory when a native report is
relocated ([INV-GHSA-4](#inv-ghsa-4)). After the move the advisory is GHSA-linked
and everything below governs it. The mirror covers the *pre-publication* lifecycle
too: a GHSA-linked advisory's initial `state` is derived from GitHub's
`ghsa_state` at creation — `triage` when the GHSA is still in triage upstream (a
private vulnerability report not yet accepted into a draft), else `draft`. A
GHSA-linked `triage` row is **read-only**: it carries no human triage affordances
(`can_triage` and `can_flag_for_admin_routing` return `False` for it; it is kept
out of the admin-console Inbox) and advances only by mirroring GitHub — forward
to `draft` when GitHub accepts the report into a draft (`react_to_ghsa_state`,
state-only flip, forward-only — a `draft` is never demoted back to `triage`), to
`published` via auto-publish, or to `dismissed` via auto-dismiss. Discovery feeds
this both on demand and via two pushes: the `repository_advisory.reported`
webhook auto-creates a row for a newly-reported GHSA, and a slow beat-scheduled
discovery sweep (`run_scheduled_ghsa_discovery`, every `GHSA_DISCOVERY_INTERVAL_HOURS`)
backstops `reported` webhooks GitHub may not deliver.

When an observed sync (webhook, manual, or the
periodic reconcile) finds the linked GHSA `published` and the AdvisoryHub
advisory in `draft` or `triage`, AdvisoryHub **auto-publishes** it — exporting
OSV/CSAF/CVE through the normal publication pipeline via `publish(system=True)`,
which skips the human `can_publish` gate (the decision is GitHub's) but keeps
every other guard (dismissed block, in-flight lock, `refresh_for_publish`). The
trigger keys off the *current* state, not a delta, so a missed `published` event
self-heals on the next sync; the `state ∈ {draft, triage}` guard plus `publish()`'s
in-flight lock keep it idempotent and dedupe a webhook-vs-reconcile double fire;
a dismissed advisory is never auto-published. When the advisory is already
`published` and a sync moves its content (`republish_required` set), AdvisoryHub
**auto-re-publishes** through the same path — keyed on the GHSA still being
`published` upstream, so it never collides with the `gone` branch below. Both are
gated by `GHSA_AUTO_PUBLISH_ENABLED` (default on).

Because publication strictly follows the GHSA, there is **no human publish step**
for a GHSA-linked advisory: `can_publish` returns `False` for owners
(project security team), so they get no Publish/Re-publish button — clicking it
would be a no-op decision, since `refresh_for_publish` only lets a publish through
once the GHSA is already `published` upstream. Global admins retain a manual
**break-glass** (the `is_global_admin` short-circuit in `can_publish`) to re-drive
a stuck/failed run or publish while `GHSA_AUTO_PUBLISH_ENABLED` is off; that path
is still GHSA-state-gated by `refresh_for_publish`, so an admin cannot push a
GHSA-linked advisory public ahead of GitHub.

Symmetrically, when an observed sync finds the linked GHSA **closed**,
**withdrawn**, or **deleted** (404 / `missing_upstream`), AdvisoryHub mirrors it:
a `draft`/`triage` advisory is **auto-dismissed** (`dismiss_advisory`), and a
`published` advisory is **auto-withdrawn** (`withdraw_advisory`, [INV-WITHDRAW](#inv-withdraw)) —
the OSV/CSAF are re-exported marked withdrawn and it moves to `dismissed`; the
document is never deleted. Both run with the system actor (`None`). An advisory
holding an `assigned_cve_id` is **not** auto-dismissed or auto-withdrawn:
orphaning an EF CVE is a CNA action that `can_dismiss` / `can_withdraw_published`
keep admin-only, so the system never performs it — the row is left flagged for an
admin. The periodic reconcile therefore sweeps `draft`/`triage`/`published`
GHSA-linked advisories.

**Rationale.** GitHub's repository advisory is the authoritative artifact for a
GHSA-linked vulnerability; once GitHub discloses it, the EF feed should mirror it
without a manual step. Driving GitHub's state *from* AdvisoryHub was deliberately
rejected (authority expansion + partial-failure complexity), so the coupling is
one-way. The reaction is decided by the *observing* callers, never inside
`refresh_for_publish`, so `publish → refresh → sync → publish` cannot recurse.

**Enforced in.**
- `ghsa/services.py` — `react_to_ghsa_state` (the triage→draft promotion plus the
  auto-publish / auto-re-publish / auto-dismiss / auto-withdraw decision), called by the webhook
  dispatcher, the manual single-sync task, and `create_ghsa_linked_advisory`;
  **not** called from `refresh_for_publish`. `create_ghsa_linked_advisory`
  derives the initial `state` from the synced `ghsa_state` (triage vs draft).
  `_dispatch_repository_advisory_event` auto-creates on
  `published`/`updated`/`edited`/`reopened`/**`reported`**.
  `reconcile_ghsa_linked_advisories` sweeps `draft`/`triage`/`published`.
- `advisories/permissions.py` — `can_triage` / `can_flag_for_admin_routing`
  return `False` for GHSA-linked rows (read-only triage mirror); `can_publish`
  returns `False` for GHSA-linked rows except via the `is_global_admin`
  break-glass (publication is system-driven, not owner-initiated).
- `admin_console/views/inbox.py` — GHSA-linked rows excluded from the triage
  work queue and its count.
- `ghsa/tasks.py` — `run_ghsa_auto_publish` (best-effort; a gating refusal —
  CVE conflict / missing upstream / concurrent run — is caught and skipped);
  `run_scheduled_ghsa_discovery` (beat backstop, no-ops while the feature is off).
- `config/settings/base.py` — `GHSA_DISCOVERY_INTERVAL_HOURS` + the
  `ghsa-discovery` beat entry.
- `publication/services.py` — `publish(system=True)` skips `can_publish` while
  keeping the dismissed / in-flight guards; the GHSA `refresh_for_publish` is
  skipped for a withdrawal (`withdrawn_reason` set), since the GHSA is gone.
- `advisories/services.py` — `dismiss_advisory` (draft/triage) and
  `withdraw_advisory` (published, [INV-WITHDRAW](#inv-withdraw)); the system path
  only reaches them for a CVE-free advisory.
- `config/settings/base.py` — `GHSA_AUTO_PUBLISH_ENABLED`.

**Violation impact.** A GitHub-published advisory silently fails to reach the EF
OSV/CSAF feed; a GitHub-withdrawn advisory keeps masquerading as a live draft; or
AdvisoryHub mutates a maintainer's GitHub advisory it should not.

**Tests.** `ghsa/tests/test_inbound_lifecycle.py`,
`ghsa/tests/test_integration_publish.py`, `publication/tests/test_pipeline.py`,
`advisories/tests/test_permissions.py`.

**Related.** [INV-GHSA-1](#inv-ghsa-1), [INV-GHSA-2](#inv-ghsa-2),
[INV-LIFECYCLE-3](#inv-lifecycle-3), [INV-GHSA-4](#inv-ghsa-4).

---

<a id="inv-ghsa-4"></a>
### INV-GHSA-4 — "Move to GHSA" is the one sanctioned outbound create + kind flip   [High]

**Statement.** When a vulnerability was filed as a **native** AdvisoryHub report
(`triage` or `draft`) that should have been a private vulnerability report on
GitHub, an owner may **move it to GHSA**: AdvisoryHub authors a repository
security advisory on a chosen GitHub repo from the report's content
(`create_repository_advisory`, the single outbound *create* in the bridge —
[INV-GHSA-3](#inv-ghsa-3)) and converts the advisory **in place** to GHSA-linked
(`kind` `native` → `ghsa_linked`, `ghsa_id`/`ghsa_owner`/`ghsa_repo` set). This is
the **only** sanctioned `kind` flip — every other surface treats `kind` as
immutable (`Advisory.clean()`), and the move runs through a dedicated service that
saves directly rather than through a form, so the immutability guard still blocks
all human edits. After the move the row follows the normal inbound lifecycle
([INV-GHSA-3](#inv-ghsa-3)): its content syncs from GitHub and is read-only, and
publication is GitHub-driven.

**Constraints.**
- **Eligibility / authorization.** Owner-only (project security team or global
  admin), gated on `GHSA_FEATURE_ENABLED`, native `kind`, state ∈ {`triage`,
  `draft`}. An `assigned_cve_id` does **not** block the move — GHSA-linked
  advisories support CVEs, and the assigned CVE is carried into the create payload
  (`cve_id`) so the new GHSA records it and the follow-up sync raises no conflict.
- **Target repo.** Must be an **active repo of the advisory's own project**, so
  the GHSA-linked project stays PMI-consistent ([INV-GHSA-1](#inv-ghsa-1) — the
  project does not change across the move), and must have **private vulnerability
  reporting (PVR) enabled** right now (re-validated live against GitHub at move
  time, not merely from the cached `ProjectGitHubRepository.pvr_enabled` flag used
  to gate the UI). Step-up re-authentication is required.
- **Atomicity.** The GitHub create happens before the local flip; the flip, audit
  (`ADVISORY_MOVED_TO_GHSA`), version append, and state mirroring commit together.
  A GitHub failure leaves the advisory untouched (still native). A rare partial —
  GHSA created on GitHub but the local commit lost — self-heals via discovery
  (idempotent `create_ghsa_linked_advisory` returns the row by `ghsa_id`).

**Rationale.** Relocating a misfiled report should not force the owner to
re-author it by hand on GitHub and dismiss the copy. Creating the GHSA *from* the
report and converting the same row keeps the advisory's identity, grants,
comments, and history intact, and is a one-way authoring action — it establishes
the link, it does not drive an existing GHSA's lifecycle, so it is consistent with
the inbound-only rule.

**Enforced in.**
- `ghsa/services.py` — `move_advisory_to_ghsa` (guards + outbound create + in-place
  flip + sync/mirror + version + audit), `build_repository_advisory_payload`,
  `refresh_pvr_status`.
- `ghsa/client.py` — `create_repository_advisory`, `get_private_vulnerability_reporting`.
- `advisories/permissions.py` — `can_move_to_ghsa` (cheap, cache-based UI gate).
- `advisories/views.py` — `advisory_move_to_ghsa_modal` / `advisory_move_to_ghsa`
  (step-up, rate limit, server-side re-check).
- `advisories/models.py` — `kind` immutability in `clean()` (the move is the
  documented exception, performed via service save, not a form).

**Violation impact.** A misfiled report can't be relocated, or the conversion
leaves a half-linked row (native content with GHSA ids, or a GHSA-linked row whose
project no longer matches its source repo), corrupting the inbound mirror.

**Tests.** `ghsa/tests/test_move_to_ghsa.py`, `advisories/tests/test_permissions.py`.

**Related.** [INV-GHSA-1](#inv-ghsa-1), [INV-GHSA-3](#inv-ghsa-3),
[INV-VERSION-1](#inv-version-1).

---

## 20. LLM duplicate detection (similarity)

<a id="inv-sim-1"></a>
### INV-SIM-1 — Duplicate-check results are owner-only   [Critical]

**Statement.** The duplicate-check panel and both `similarity` endpoints
(`similarity:panel`, `similarity:run`) are visible only to users whose
resolved permission on the advisory is `owner` (global admins and the
project security team). Collaborators, viewers, and anonymous users are
rejected server-side; the `similarity_enabled` flag the detail template
consumes is display-only.

**Rationale.** Check results enumerate other advisories in the same project
(ids, confidence, rationale). Because the comparison corpus is
same-project only, every owner of the checked advisory is an owner of
every match — `owner` is exactly the safe audience. Anything weaker leaks
the existence and substance of advisories a per-advisory grantee has no
access to.

**Enforced in.**
- `similarity/views.py` — `_gated_advisory` requires `resolved_permission == "owner"`.
- `advisories/views.py` — `advisory_detail` sets the display-only `similarity_enabled` flag.

**Violation impact.** Per-advisory grantees (collaborator/viewer) learn about
other same-project advisories, including embargoed ones.

**Tests.** `similarity/tests/test_views.py` (permission matrix, loader gating).

**Related.** [INV-AUTH-1](#inv-auth-1), [INV-PRIVACY-1](#inv-privacy-1),
[INV-SIM-2](#inv-sim-2).

---

<a id="inv-sim-2"></a>
### INV-SIM-2 — Disabled by default; no content egress while off   [Critical]

**Statement.** With `SIMILARITY_CHECK_ENABLED=False` (the default), no
advisory content leaves the deployment through the similarity feature:
`request_check` returns `None` before creating any row or enqueue (the
single egress gate every trigger funnels through), both endpoints return
404, the detail page renders no panel, and `backfill_fingerprints`
refuses with a `CommandError`. Enabling the flag is the operator's
explicit consent for sending advisory content — potentially embargoed —
to the configured LLM provider.

**Rationale.** Embargoed vulnerability details must never flow to a third
party as a side effect of an upgrade or a stray trigger. Deployments
needing on-prem inference set `SIMILARITY_LLM_PROVIDER=openai` with
`SIMILARITY_LLM_BASE_URL` pointing at a local OpenAI-compatible server.

**Enforced in.**
- `similarity/services.py` — `request_check` flag gate.
- `similarity/views.py` — `Http404` while disabled.
- `similarity/management/commands/backfill_fingerprints.py` — `CommandError` while disabled.

**Violation impact.** Silent exfiltration of embargoed advisory content to an
external service.

**Tests.** `similarity/tests/test_services.py`, `similarity/tests/test_views.py`,
`similarity/tests/test_triggers.py`, `similarity/tests/test_backfill.py`
(disabled-flag cases).

**Related.** [INV-SIM-1](#inv-sim-1), [INV-SIM-3](#inv-sim-3).

---

<a id="inv-sim-3"></a>
### INV-SIM-3 — LLM errors are redacted; the API key never persists   [Critical]

**Statement.** Strings stored in `SimilarityCheck.last_error` and similarity
audit metadata never contain the provider API key or other credentials.
`LlmError` messages are built from the HTTP status plus a response-body
excerpt only — request headers, where the key travels, are never
interpolated — and pass through `audit.services.redact_secrets` at
construction; `mark_failed` redacts again and caps at 8000 chars.

**Rationale.** Provider failures surface in the owner-facing panel and in the
audit trail; a credential there is an immediate compromise of the LLM
account.

**Enforced in.**
- `similarity/llm/base.py` — `LlmError` and `_post` error construction.
- `similarity/services.py` — `mark_failed`.
- `similarity/tasks.py` — `_fail` passes the already-redacted `last_error` to audit.

**Violation impact.** LLM API key leak to the advisory page, audit log, or
application logs.

**Tests.** `similarity/tests/test_llm_client.py` (exhausted-retry error carries
no key), `similarity/tests/test_pipeline.py` (failure path),
`similarity/tests/test_services.py` (`mark_failed`).

**Related.** [INV-SECRET-1](#inv-secret-1), [INV-AUDIT-2](#inv-audit-2).

---

<a id="inv-sim-4"></a>
### INV-SIM-4 — Checks judge pinned version content   [High]

**Statement.** The fingerprint and judge inputs for the checked advisory are
built from the `SimilarityCheck.version` payload pinned at request time —
never from live form data — and the version FK is `on_delete=PROTECT`.
The `AdvisoryFingerprint` cache is keyed on a content hash of the
duplicate-relevant payload subset and is **not** part of
`Advisory.to_payload()`, so fingerprint writes never append
`AdvisoryVersion` rows.

**Rationale.** Stored results must describe an immutable, auditable input —
the same contract OSV/CSAF generation honours. A mutable input would make
a persisted confidence score unexplainable after the next edit.

**Enforced in.**
- `similarity/models.py` — `version` FK `PROTECT`; `AdvisoryFingerprint` sidecar.
- `similarity/services.py` — `run_check_sync` reads `check.version.payload`;
  `ensure_fingerprint` re-keys on the content hash.

**Violation impact.** Results that cannot be traced to the content they
scored; version rows deletable out from under recorded checks.

**Tests.** `similarity/tests/test_pipeline.py`,
`similarity/tests/test_services.py` (fingerprint staleness).

**Related.** [INV-VERSION-2](#inv-version-2), [INV-VERSION-3](#inv-version-3).

---

<a id="inv-sim-5"></a>
### INV-SIM-5 — Stale similarity checks are bounded   [High]

**Statement.** A beat-scheduled reaper (`similarity.reap_stale_similarity_checks`,
every 10 minutes) flips `SimilarityCheck` rows stuck in `running` past
`SIMILARITY_CHECK_STALE_RUNNING_AFTER_SECONDS` (default 1800 s, measured from
`started_at`) or in `queued` past `SIMILARITY_CHECK_STALE_QUEUED_AFTER_SECONDS`
(default 7200 s, measured from `created_at`) to `failed`. Each reap is a
per-row compare-and-set under `select_for_update(skip_locked=True)`: a row
finalised concurrently falls out of the status filter and is skipped, never
clobbered. The reaper is DB-only janitor work — it performs **no** LLM egress
([INV-SIM-2](#inv-sim-2) unaffected) and therefore runs even while
`SIMILARITY_CHECK_ENABLED` is off, clearing rows wedged from when the feature
was on. It never mutates `Advisory` rows.

**Rationale.** A worker hard-killed mid-run (hard `time_limit` SIGKILL, OOM
kill, pod eviction) leaves a row in `running` that the redelivered message
no-ops against (the entry guard accepts only queued/failed); a broker outage
swallowed by `safe_enqueue` leaves a `queued` row with no message at all.
Either row wedges `request_check`'s in-flight guard forever — and the panel
view swallows `SimilarityCheckInProgress`, so the re-run button silently does
nothing and the panel shows "pending" indefinitely. The thresholds sit above
the physical constants they are anchored to (the 360 s hard `time_limit`; the
3600 s broker `visibility_timeout`), so the reaper can never race a live
execution or a pending redelivery.

**Enforced in.**
- `similarity/services.py` — `reap_stale_checks` / `_reap_one`.
- `similarity/tasks.py` — `reap_stale_similarity_checks`.
- `config/settings/base.py` — `CELERY_BEAT_SCHEDULE["similarity-check-reaper"]`,
  `SIMILARITY_CHECK_STALE_*` knobs.

**Violation impact.** Duplicate detection permanently dead for the affected
advisory, with no recovery short of manual SQL.

**Tests.** `similarity/tests/test_reaper.py`.

**Related.** [INV-PUB-7](#inv-pub-7) and [INV-GHSA-2](#inv-ghsa-2) (the
publication and GHSA mirrors of this rule), [INV-SIM-2](#inv-sim-2),
[INV-SIM-3](#inv-sim-3).

---

## 21. Data confidentiality at rest

<a id="inv-conf-1"></a>
### INV-CONF-1 — Content confidentiality at rest is a deployment control, not app-layer encryption   [High]

**Statement.** Advisory content is **not** encrypted at the application layer.
The fields the app queries — `summary`, `details`, `aliases`, `affected` — are
stored as plaintext, SQL-queryable columns/JSONB, and the full payload is kept
in clear in the append-only `AdvisoryVersion.payload`. Confidentiality of that
content at rest (against a stolen-credential or stolen-media attacker) is
provided by deployment-layer controls on the database access path — documented
in [running-in-production.md §7](../operations/running-in-production.md#7-database-hardening-checklist)
— not by column encryption.

**Rationale.** App-layer encryption would defeat credential theft only with a
key held in a separate trust domain (KMS/HSM); in practice the DB password and
any key share one secret store and pod, and a compromised app process holds the
key anyway — so it adds little against the headline threat while breaking
features that need plaintext: advisory search and the duplicate-detection
prefilter ([INV-SIM-4](#inv-sim-4)) both run SQL `LIKE`/trigram/JSONB queries
over these columns. Encrypting the append-only payload
([INV-IMPL-5](#inv-impl-5)) would also make key loss equal permanent loss of
immutable history. The architectural discussion is in
[architecture.md §3.9](./architecture.md#39-data-confidentiality-and-the-database-compromise-threat).

**Enforced in.**
- `advisories/views.py`, `api/views_advisories.py` — search over plaintext
  `summary`/`details`/`aliases`.
- `similarity/prefilter.py` — `TrigramSimilarity` + JSONB `__contains` prefilter
  that depends on plaintext content.
- Deployment controls (network isolation, TLS, least-privilege role, encrypted
  backups, DB-level audit) live in
  [running-in-production.md §7](../operations/running-in-production.md#7-database-hardening-checklist).

**Violation impact.** Encrypting these columns silently breaks advisory search
and duplicate detection; encrypting `AdvisoryVersion.payload` risks
unrecoverable loss of immutable history. Conversely, treating disk/TDE
encryption as protection against stolen *credentials* gives a false sense of
confidentiality — that threat needs the access-path controls, not
encryption-at-rest.

**Tests.** `advisories/tests/test_list_filters.py` (plaintext search) and the
`similarity/` prefilter suite. _(No dedicated negative test — this is a
posture/design invariant; the search and similarity suites assert the plaintext
queries on which it rests.)_

**Related.** [INV-PRIVACY-1](#inv-privacy-1), [INV-AUTH-7](#inv-auth-7),
[INV-AUDIT-1](#inv-audit-1), [INV-SECRET-1](#inv-secret-1),
[INV-SIM-4](#inv-sim-4), [INV-IMPL-5](#inv-impl-5).

---

## 22. Data isolation and authorization defense-in-depth

<a id="inv-conf-2"></a>
### INV-CONF-2 — Advisory visibility is enforced below the app by row-level security; tenancy is not used   [High]

**Statement.** Cross-project / cross-grant advisory visibility is enforced at
two layers. The application chokepoint is `Advisory.objects.visible_to(user)`
(wrapped by `advisories.permissions.visible_advisories`); below it, Postgres
**row-level security** on `advisories_advisory` — and predicate-free deferring
policies on its `advisory_id` child tables — re-enforces the *same* rule on every
query, so a view that forgets to filter (or an object fetched directly by id)
still returns only rows the principal may see. The policy is keyed on a
per-request principal carried in session GUCs (`advisoryhub.user_id`,
`advisoryhub.is_admin`); an **unset principal matches no rows** (fail-closed).
Schema-/DB-per-project tenancy is **deliberately not used**.

**Rationale.** The access boundary is `per-advisory ∪ per-project` — an
`AdvisoryAccessGrant` can name a user/group on a single advisory regardless of
project, and an authenticated triage reporter is auto-granted viewer on their own
report — so a project schema/DB would model only half the boundary, force
cross-schema access for every grant, and shard the global append-only audit
timeline ([INV-AUDIT-1](#inv-audit-1)), the partitioned access log
([INV-AUDIT-5](#inv-audit-5)), trigram search and the similarity prefilter. It
would also merely move the bug: per-schema isolation needs per-schema DB roles,
and *which role a connection may use* is again decided by app code. RLS instead
inverts the default from **opt-in / fail-open** (every query must remember to
filter) to **fail-closed** (every query is filtered unless the principal is
explicitly admin), while trusting only a trivially-correct principal (the
authenticated user id + an admin flag) that lives apart from the permission
resolution it backstops. RLS defends the *forgot-to-filter / IDOR* class —
**not** a wrong access predicate: if the logic itself is wrong, both layers are
wrong, which is why the policy is **drift-tested** to return the same id set as
`visible_to`. Discussion in
[architecture.md §3.10](./architecture.md#310-project-data-isolation-and-the-authorization-bug-threat).

**Enforced in.**
- `advisories/models.py` — `AdvisoryQuerySet.visible_to`; `advisories/permissions.py`
  — `visible_advisories` (the application chokepoint).
- `advisories/migrations/*_advisory_rls.py` — `ENABLE` / `FORCE ROW LEVEL SECURITY`
  and the `advisory_visibility` policy mirroring `visible_to`, plus deferring
  policies on the `advisory_id` child tables.
- `common/middleware.py` — `RowLevelSecurityMiddleware` sets the principal GUCs
  for a request; the `rls_principal` / `rls_system` context managers in `common`
  set them for Celery tasks and management commands. Operational probes/static
  assets (`_RLS_EXEMPT_PREFIXES`: `/healthz`, `/readyz`, `/metrics`, `/static/`)
  are exempt — they query no RLS-protected table, so skipping the principal keeps
  `/healthz` a DB-free liveness probe (and lets `/readyz` degrade to its own 503
  on a DB outage rather than a middleware 500); the fail-closed default is
  unweakened since a reused connection is always left at the empty principal.
- Operator role model (single role + `FORCE`, or app-as-non-owner-role) in
  [running-in-production.md §7](../operations/running-in-production.md#7-database-hardening-checklist).

**Violation impact.** Dropping `FORCE ROW LEVEL SECURITY`, mis-setting
`advisoryhub.is_admin`, or a policy that drifts from `visible_to` either re-opens
cross-project / cross-grant content leakage (under-denies) or breaks legitimate
access (over-denies). Reintroducing schema-/DB-per-tenant would fracture the
global audit timeline and search.

**Tests.** `tests/test_authorization_matrix.py` (endpoint × role enumeration +
capability cases); `advisories/tests/test_rls.py` (backstop proof — a forgotten
filter still returns only visible rows — and the `visible_to` ↔ RLS drift guard).

**Related.** [INV-CONF-1](#inv-conf-1), [INV-AUTH-1](#inv-auth-1),
[INV-AUTH-7](#inv-auth-7), [INV-PRIVACY-1](#inv-privacy-1),
[INV-AUDIT-1](#inv-audit-1).

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
