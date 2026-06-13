# AdvisoryHub — Requirements

This document is the top-down functional specification for AdvisoryHub. It
describes **what** the system does — the actors it serves, the domain
objects it manages, the workflows it supports, and the rules those
workflows must honour. It is paired with [`architecture.md`](./architecture.md),
which covers the **how** (technology stack, internal structure, operations).

Where a rule has a stable ID or a state-machine diagram, the deep-dive
lives in the existing specification triad and this document cross-links
to it:

- [`invariant.md`](./invariant.md) — load-bearing rules with stable
  `INV-XYZ-N` IDs.
- [`advisory-lifecycle.md`](./advisory-lifecycle.md) — state diagrams,
  transition tables, the publication sequence diagram.
- [`permissions.md`](./permissions.md) — actors, roles, capability
  matrix, enforcement surfaces.

The specification set under `docs/specification/` is the single
source of truth: code must conform to it. If this document and the
code disagree, that is a defect — either the code drifted (fix the
code) or the behavior changed deliberately without a spec update
(fix the document in the same change). Deviating from the spec
requires explicit maintainer confirmation *before* implementation.

---

## 1. Purpose & scope

AdvisoryHub is a **private** Django application for authoring, reviewing,
publishing, and auditing security advisories for Eclipse Foundation
projects. It is the system of record for advisory *content*, advisory
*workflow*, and advisory-related *governance actions* (access grants,
review decisions, CVE requests, publication attempts, audit history).

Published advisories are exported as OSV and CSAF JSON and pushed to a
separate **publication Git repository**; that repository has its own
CI/CD that renders the public-facing website. AdvisoryHub does not host
the public website, does not interact with end users who *read* the
public advisories, and does not orchestrate the publication-repo's
build. Publication is a one-way handoff: every advisory that has ever
been pushed appears as a deterministic commit on the configured branch,
and the public surface is whatever that branch becomes.

### In scope

- Authoring of advisory content (native or GHSA-linked).
- A four-state lifecycle with three orthogonal status machines
  (review, CVE request, publication).
- A private public-form intake (triage) for incoming reports.
- Access control on every advisory, with per-advisory grants and
  invitations on top of project-derived ownership.
- Comments with markdown rendering, mentions, and per-comment
  internal-vs-public scoping.
- An append-only audit log over every governance action.
- Generation, validation, and Git-push of OSV + CSAF documents.
- GHSA integration: linking advisories to GitHub Security Advisories,
  syncing metadata, pushing EF-assigned CVE IDs back to GitHub,
  ingesting webhooks, and mirroring the project↔repo map from the
  Eclipse Foundation PMI API.
- An admin console for the global security team to triage, review,
  assign CVEs, retry publications, and read the audit trail.

### Out of scope

- The public anonymous read surface (lives in the publication Git
  repo's static site).
- A real MITRE CVE-services integration — the CVE request workflow is
  an internal queue ([`invariant.md` §14](./invariant.md#14-cve-request-workflow)).
- IdP / OIDC group administration. Group membership is mirrored on
  login and never edited from AdvisoryHub
  ([INV-OIDC-1](./invariant.md#inv-oidc-1)).
- Email deliverability concerns and template content beyond the
  redaction guarantees.

---

## 2. Actors

| Actor | How identified | Default authority |
|---|---|---|
| Anonymous web client | No session | May POST a triage report to `/report/`. May follow the OIDC redirect to sign in. Nothing else. |
| Authenticated user | OIDC session | No role on any advisory by default. Sees only advisories they hold a grant for. |
| Triage reporter (authenticated) | OIDC session at submission time | Auto-granted `viewer` on the advisory they filed. |
| Triage reporter (anonymous) | None retained | No link is recorded; the report cannot later be claimed. |
| Project security-team member | Member of the Django `Group` referenced by `Project.security_team` | Derived `owner` on every advisory under that project. |
| Global admin / reviewer | Member of `OIDC_ADMIN_GROUP` | Derived `owner` everywhere; exclusive reviewer of submitted advisories; sole holder of CNA-side admin actions (unassign CVE, mark orphan rejected at cve.org, ban CVE requests). |
| Celery worker | Background process | No ambient authority — every task acts on behalf of a stored user and re-checks the relevant predicate at execution time. |

The full actor / authority detail is in
[`permissions.md` §3](./permissions.md#3-actors).

---

## 3. Domain concepts

The objects below carry the bulk of the system's state. Most are
modeled in their own Django app; cross-references point at the
corresponding model module for the full field list.

### Advisory

The central object — a security advisory about an Eclipse Foundation
project. Each advisory has a **kind** (`native` or `ghsa_linked`), one
of four **lifecycle states** (`triage` / `draft` / `published` /
`dismissed`), and an OSV-aligned content payload (`summary`, `details`,
`aliases`, `references`, `affected`, `severity`, `cwe_ids`, `credits`,
plus `assigned_cve_id` and `withdrawn_reason`). Each advisory carries
a public, immutable `advisory_id` matching `ECL-…-…-…` using a
confusion-resistant alphabet ([INV-ID-1](./invariant.md#inv-id-1)).

GHSA-linked advisories are a *bridge* over a GitHub-hosted Security
Advisory: their OSV content fields are sourced from GHSA and read-only
in AdvisoryHub; AdvisoryHub initiates CVE-ID allocation and pushes it
back to GitHub, and publication is gated on the upstream GHSA having
been published. Their owning project is derived from the source
repository's PMI ownership and follows PMI automatically — it is never
reassigned by hand ([INV-GHSA-1](./invariant.md#inv-ghsa-1)).

`Advisory.kind` is set at creation and immutable. `Advisory.delete()`
is blocked at the model and DB layers
([INV-IMPL-1](./invariant.md#inv-impl-1)).

### AdvisoryVersion

Append-only edit log of advisory content. Version 1 is seeded
automatically when the advisory is created; every payload-visible edit
appends `v(n+1)`; non-payload saves (state flips, heartbeat metadata
sync) do not. `AdvisoryVersion.save()` on an existing row and
`AdvisoryVersion.delete()` both raise
([INV-IMPL-5](./invariant.md#inv-impl-5)). Workflow tasks
(`ReviewTask`, `PublicationTask`) `PROTECT`-FK into this table so a
version that was ever pinned by a workflow cannot be removed
([INV-VERSION-2](./invariant.md#inv-version-2)).

### AdvisoryIntakeMetadata

One-to-one sidecar on triage advisories. Stores the reporter's
authenticated identity (when present), the request IP and User-Agent,
the admin-routing flag, and the time fields used to scrub PII at
retention boundaries. Reporter email is **never** taken from form
input; only an OIDC-verified email may appear (via the linked
`reporter_user`) ([INV-INTAKE-2](./invariant.md#inv-intake-2),
[INV-PRIVACY-3](./invariant.md#inv-privacy-3)).

### Project & ProjectGitHubRepository

`Project` is an Eclipse Foundation project. Carries a slug, a name, a
homepage URL, the `security_team` Django `Group`, and the
`is_mature_publisher` flag that controls whether the team may publish
without a top-level review ([INV-PERM-1](./invariant.md#inv-perm-1),
[INV-PERM-2](./invariant.md#inv-perm-2)). A singleton `unsorted`
project owns unrouted triage; its security team is the admin group by
construction ([INV-PROJECT-2](./invariant.md#inv-project-2)).

`ProjectGitHubRepository` mirrors the `(owner, name)` pairs that PMI
declares for a project. The mirror is refreshed by a Celery beat task
and used by the GHSA discovery flow to know which repos to query.

`SecurityTeamRosterEntry` mirrors the PMI security-team roster for a
project (dormant unless `PMI_ROSTER_SYNC_ENABLED`). The roster sync
pre-provisions notification-only *shadow* users
(`User.is_provisioned=True`) so triage events and `@team` mentions
reach members who have never logged in; shadows belong to no group,
hold no authorization, and are linked to the real account on first
login ([INV-OIDC-5](./invariant.md#inv-oidc-5),
[INV-ROSTER-1](./invariant.md#inv-roster-1)).

### AdvisoryAccessGrant & PendingInvitation

`AdvisoryAccessGrant` carries one grant per `(advisory, principal_type,
principal_id)` ([INV-ACCESS-1](./invariant.md#inv-access-1)).
`principal_type` is `user` or `group`; `permission` is `viewer` or
`collaborator`. The grant table never carries `owner` —
ownership is structural, not grantable
([INV-AUTH-3](./invariant.md#inv-auth-3),
[INV-ACCESS-4](./invariant.md#inv-access-4)).

`PendingInvitation` is the email-address-keyed staging row used when an
owner invites someone who does not yet have a Django user. Redemption
matches the authenticated user's email case-insensitively
([INV-ACCESS-2](./invariant.md#inv-access-2)) and refuses expired rows
([INV-ACCESS-3](./invariant.md#inv-access-3); default lifetime 14 days).

### AdvisoryComment & CommentVersion

Comments on an advisory. Each comment has an author, a markdown
`body`, and an `is_internal` boolean fixed at creation
([INV-COMMENT-1](./invariant.md#inv-comment-1)). Markdown is rendered
on demand through a strict nh3 allowlist — no inline HTML, no
images, no scripts; rendered HTML is never stored. `@mentions`
resolve to users by full email or local-part.

`CommentVersion` is the append-only edit history; redaction sets
`redacted_at` and clears the visible body but preserves the row's
place in the timeline ([INV-COMMENT-3](./invariant.md#inv-comment-3),
[INV-COMMENT-4](./invariant.md#inv-comment-4)).

### AuditLogEntry & AccessLogEntry

One append-only row per governance action, recording the actor,
timestamp, action type, advisory (and optionally the comment id),
previous and new values, IP, User-Agent, and a JSON metadata blob.
Both the application layer and a Postgres trigger refuse `UPDATE` and
`DELETE` ([INV-AUDIT-1](./invariant.md#inv-audit-1)). All
user/CI-supplied strings pass through `audit.services.redact_secrets`
before persistence ([INV-AUDIT-2](./invariant.md#inv-audit-2)).

`AccessLogEntry` is the companion high-volume table for *ephemeral*
events that never appear on an advisory timeline — advisory views,
auth events (login, logout, failed login, step-up re-auth),
notification deliveries, and GHSA/PMI machine chatter. Unlike the
durable ledger it is range-partitioned by month and
retention-managed: partitions older than
`AUDIT_ACCESS_LOG_RETENTION_DAYS` (default 90) are dropped by a beat
task ([INV-AUDIT-5](./invariant.md#inv-audit-5)).

### NotificationPreference, AdvisoryNotificationPreference, Notification

`NotificationPreference` is one row per user holding the global
notification defaults; `AdvisoryNotificationPreference` is a *sparse*
per-advisory override (any field at its inherit sentinel uses the
global setting; rows with every field at the sentinel are deleted).

`Notification` is the per-recipient in-app inbox row created alongside
each delivered email; users mark entries read explicitly or implicitly
by visiting the page the notification points at. `AdvisoryVisit` (one
row per user/advisory) records the last visit and powers the
"changed since last visit" markers on advisory lists.

### CveRequestTask, ReviewTask, OrphanCve, OrphanCveReassignmentTask

The workflow queues attached to an advisory. `CveRequestTask`
tracks the request lifecycle (`queued` → `reserved | rejected |
cancelled`) with at most one open task per advisory
([INV-CVE-1](./invariant.md#inv-cve-1)). `ReviewTask` pins the exact
`AdvisoryVersion` a reviewer is judging
([INV-REVIEW-2](./invariant.md#inv-review-2)). `OrphanCve` records
admin-initiated CVE unassignments so admins remember to mark the CVE
rejected at cve.org. `OrphanCveReassignmentTask` queues admin
follow-up when an advisory is reopened after its orphaned CVE was
already marked rejected — the admin either reattaches the CVE or
replaces it with a fresh request (see
[`advisory-lifecycle.md` §3.1](./advisory-lifecycle.md)).

### PublicationTask, PublicationArtifact, PublicationRepositoryConfig

`PublicationTask` is one row per publish or re-publish attempt,
pinning the `AdvisoryVersion` that was (or will be) exported, with a
status of `queued` / `running` / `succeeded` / `failed`.
`PublicationArtifact` is one row per `(task, kind ∈ {osv, csaf,
cve})` holding the validated JSON document that was pushed (the `cve`
kind exists only when the advisory carries an EF-assigned CVE); it is
also the data source for the admin-console preview screens.
`PublicationRepositoryConfig` carries the per-repository settings
(URL, branch, auth method, key/token, commit author, OSV / CSAF /
CVE-record path templates, and the CVE assigner identity).

### GHSA integration objects

`GitHubAppInstallation` records the per-organization GitHub App
installation that AdvisoryHub authenticates as. `WebhookDelivery`
deduplicates inbound webhooks by delivery ID. `GhsaCvePushTask` is one
queued/running/finished row per attempt to push an EF-assigned CVE
back to a linked GHSA. `GhsaSyncRun` is one row per sync operation
(single advisory / one project / all projects / PMI mirror) with
counts and last-error redaction.

### HoneypotSubmission

One row per honeypot trip on the public intake form. No `Advisory` is
created; the response page is identical to a real submission so bots
learn nothing ([INV-INTAKE-1](./invariant.md#inv-intake-1)).

### SimilarityCheck, SimilarityCandidate, AdvisoryFingerprint

The duplicate-detection rows (`similarity` app; dormant unless
`SIMILARITY_CHECK_ENABLED` — see §4.13). `SimilarityCheck` is one row
per LLM-assisted duplicate check, pinning the `AdvisoryVersion`
payload it judged ([INV-SIM-4](./invariant.md#inv-sim-4)) with a
queued/running/succeeded/failed status and a redacted `last_error`
([INV-SIM-3](./invariant.md#inv-sim-3)). `SimilarityCandidate` stores
the judged matches (a 0–100 confidence plus a one-line rationale,
top five per check). `AdvisoryFingerprint` caches the per-advisory
LLM digest, keyed on a content hash so unchanged content is never
re-digested.

---

## 4. Functional requirements

### 4.1 Advisory content & validation

Advisory content fields are modeled after the OSV schema:

| Field | Type | Notes |
|---|---|---|
| `advisory_id` | string | Public id matching `ECL-([23456789cfghjmpqrvwx]{4}-){2}[23456789cfghjmpqrvwx]{4}`. Generated at creation, immutable. |
| `project` | FK | Eclipse Foundation `Project`. May be changed by an owner; appended to the version log and resets approval. |
| `summary` | string (≤300) | Short headline. |
| `details` | text | Markdown-flavoured long description. |
| `aliases` | list[string] | Other identifiers (CVE IDs, vendor IDs, GHSA IDs, …). |
| `references` | list[{type, url}] | `type` ∈ `{ADVISORY, ARTICLE, DETECTION, DISCUSSION, REPORT, FIX, INTRODUCED, GIT, PACKAGE, EVIDENCE, WEB}` (default `WEB`). |
| `affected` | list[{package, ranges?, versions?}] | OSV-style. Each entry needs `package.name` and at least one of `ranges` / `versions`. Each range needs a `type`, a list of events, and at least one `introduced` event; `fixed` and `last_affected` are mutually exclusive within a range. |
| `severity` | list[{type, score}] | `type` ∈ `{CVSS_V2, CVSS_V3, CVSS_V4, Ubuntu}`; Ubuntu scores are `negligible/low/medium/high/critical`. |
| `cwe_ids` | list[string] | Each `CWE-N`; validated against a vendored catalogue. |
| `credits` | list[{name, type?}] | `type` ∈ the OSV credit-type enum. |
| `published_at` / `modified_at` | datetime | `modified_at` is `auto_now`. `published_at` is set on first successful publish. |
| `withdrawn_reason` / `dismissed_reason` | text | The latter is required when the lifecycle state is `dismissed`. |
| `assigned_cve_id` | string | EF-assigned CVE id (write-once via the CVE workflow). Validated as `CVE-YYYY-NNNN…`. Effectively immutable after first assignment ([INV-CVE-2](./invariant.md#inv-cve-2)). |
| `republish_required` | bool | Set when a published advisory is edited; cleared on next successful publish. |
| `access_review_required_at` | datetime | Set when the project is reassigned; surfaces an access-review banner until dismissed. |

GHSA-linked advisories additionally carry `ghsa_id` (unique-when-set
[INV-ID-2](./invariant.md#inv-id-2)), `ghsa_owner`, `ghsa_repo`,
`ghsa_metadata` (raw payload), `ghsa_state`, `ghsa_metadata_synced_at`,
and the `ghsa_cve_push_*` fields that track our outbound push of an
EF-assigned CVE to GHSA. For these advisories the OSV-content fields
are populated from GHSA and read-only in the AdvisoryHub edit form.

Field-level validators live in `advisories.validators`. The advisory
id format is also enforced at the URL converter and at the model layer.

### 4.2 Advisory lifecycle

Lifecycle states are exactly four
([INV-LIFECYCLE-1](./invariant.md#inv-lifecycle-1)):

| State | Meaning | Created by |
|---|---|---|
| `triage` | Untrusted incoming report awaiting promotion. | Public intake only ([INV-LIFECYCLE-2](./invariant.md#inv-lifecycle-2)). |
| `draft` | Curated content being prepared for publication. | `advisory_create` view, GHSA link, or promotion from triage. |
| `published` | Successfully pushed to the publication Git repo. | Only via the publication worker's success branch ([INV-LIFECYCLE-3](./invariant.md#inv-lifecycle-3)). |
| `dismissed` | Rejection (duplicate, not-a-vuln, out-of-scope) — reversible, not terminal ([INV-LIFECYCLE-4](./invariant.md#inv-lifecycle-4)). | `dismiss_triage` (from triage) or `advisory_dismiss` (from draft). |

Three orthogonal status machines ride alongside the lifecycle and are
documented in full in
[`advisory-lifecycle.md`](./advisory-lifecycle.md):

- **Review** (`Advisory.review_status`): `none` → `submitted` →
  `approved | changes_requested` (a withdrawal returns it to `none`;
  `withdrawn` exists only on `ReviewTask.status`). Submission freezes the
  current `AdvisoryVersion`; subsequent edits to the advisory append
  versions but do not move the pinned one. Editing an `approved`
  draft by a non-admin invalidates the approval
  ([INV-REVIEW-4](./invariant.md#inv-review-4)). Admins cannot submit
  or withdraw — they are the reviewers
  ([INV-REVIEW-3](./invariant.md#inv-review-3)).
- **CVE request** (`CveRequestTask.status`): `queued` → `reserved |
  rejected | cancelled`. Dismissing a draft auto-cancels the open
  task; the admin may also flip `cve_requests_banned` on rejection
  ([INV-CVE-3](./invariant.md#inv-cve-3)).
- **Publication** (`PublicationTask.status`): `queued` → `running` →
  `succeeded | failed`. The flip to `state=published` happens only
  inside the success branch, only after `git push` returns clean
  ([INV-LIFECYCLE-3](./invariant.md#inv-lifecycle-3),
  [INV-PUB-4](./invariant.md#inv-pub-4)).

**Reopen.** Dismissal is reversible: `reopen_advisory` (owner-gated)
returns the advisory to `Advisory.dismissed_from_state` (`draft` or
`triage`), audited as `ADVISORY_REOPENED`
([INV-LIFECYCLE-4](./invariant.md#inv-lifecycle-4)). If the advisory
had a CVE that was orphaned on dismissal, reopening either reattaches
it directly or — when the orphan was already marked rejected at
cve.org — queues an `OrphanCveReassignmentTask` for admin resolution.

The full state diagrams, transition tables, and the publication
sequence diagram are in
[`advisory-lifecycle.md` §3, §5, §6, §7, §8](./advisory-lifecycle.md).

### 4.3 Public intake (triage)

A public form at `/report/` accepts anonymous and authenticated
submissions. Successful submissions create an
`Advisory(state=triage)` + `AdvisoryIntakeMetadata` sidecar via
`advisories.services.submit_triage_report`. Required fields:

- `project_slug` — a PMI project id or the literal `__unsorted__`
  sentinel ("I don't know"), which routes the advisory to the
  `unsorted` project and sets `needs_admin_routing=True`
  ([INV-INTAKE-4](./invariant.md#inv-intake-4)).
- `summary` and `details` (markdown).
- Optional `reporter_display_name` for crediting on the resulting
  advisory. Display-only and never used for authorization
  ([INV-PRIVACY-3](./invariant.md#inv-privacy-3)).

The form has **no reporter-email field**. Email is derived only from
the authenticated user's OIDC profile; anonymous submissions cannot be
re-associated with a user later
([INV-INTAKE-2](./invariant.md#inv-intake-2)).

Anti-abuse:

- Honeypot field rendered only to bots (anonymous form only). A trip
  persists a `HoneypotSubmission` row and renders the same thank-you
  page as a real submission
  ([INV-INTAKE-1](./invariant.md#inv-intake-1)).
- Optional hCaptcha when both `HCAPTCHA_SITE_KEY` and
  `HCAPTCHA_SECRET_KEY` are configured.
- Rate limits keyed per-IP for anonymous submitters and per-user for
  authenticated ones, with `RATELIMIT_INTAKE_ANON` /
  `RATELIMIT_INTAKE_USER` configurable.

Authenticated reporters are auto-granted `viewer` on the new advisory
([INV-INTAKE-3](./invariant.md#inv-intake-3)) so they can track it
from their dashboard. Triage advisories are owner-only for editing,
publishing, CVE requesting, and internal commenting
([INV-AUTH-5](./invariant.md#inv-auth-5)); the reporter's auto-grant
gives read and public-comment only.

The triage queue and per-advisory detail pages live under the admin
console's Inbox section; admins can promote
(`promote_triage_to_draft`), dismiss (`dismiss_triage`), reassign the
project (`reassign_triage_project`), and flag /unflag for admin
routing (`flag_for_admin_routing` / `clear_admin_routing_flag`). Once
flagged, the advisory becomes admin-only for triage decisions
([INV-AUTH-6](./invariant.md#inv-auth-6)). The `unsorted` project's
`security_team` is the admin group by construction, so admin routing
falls out of normal permission resolution
([INV-PROJECT-2](./invariant.md#inv-project-2)).

### 4.4 Comments

Comments are authored by the requesting user. The form accepts
markdown; the body is stored as raw markdown and re-rendered on every
read through a strict nh3 allowlist (`p`, `br`, `strong`, `em`,
`u`, `code`, `pre`, `blockquote`, `hr`, `ul`, `ol`, `li`, `h1`–`h6`,
`a`, tables). Anchor tags are augmented with `rel="nofollow noopener"`.
Rendered HTML is never persisted, so tightening the allowlist applies
retroactively.

`is_internal` is a per-comment boolean fixed at creation
([INV-COMMENT-1](./invariant.md#inv-comment-1)). Internal comments
are visible only to collaborators and owners; visibility is
re-checked at *read* time so a revoked collaborator stops seeing
internal comments immediately
([INV-COMMENT-2](./invariant.md#inv-comment-2)).

Mentions are written as `@email` or `@local-part`; the parser
resolves them against the user table and emits a mention notification
to the resolved user. A mention does not elevate visibility: if the
mentioned user lacks collaborator access on an internal comment, no
mention email is sent.

Edits append a `CommentVersion` row carrying the new body
([INV-COMMENT-3](./invariant.md#inv-comment-3)) and emit
`COMMENT_EDITED` to the audit log. Redaction stamps `redacted_at` and
`redacted_by`, clears the visible body, and is irreversible
([INV-COMMENT-4](./invariant.md#inv-comment-4)).

### 4.5 Audit log

Every governance action emits exactly one `AuditLogEntry`
([INV-AUDIT-3](./invariant.md#inv-audit-3)). The authoritative
catalogue of recordable actions is the `Action` enum in
`audit/models.py`; the event categories it covers are:

- Advisory lifecycle: created, viewed, edited, state changed, project
  changed, published, dismissed.
- Review: submitted, approved, changes requested, approval revoked,
  approval invalidated, withdrawn, task status changed.
- Access: granted, revoked; invitation created, redeemed, revoked.
- Comments: created, edited, redacted.
- CVE request: requested, task status changed, request banned,
  request cancelled, CVE unassigned, marked rejected at cve.org.
- Publication: export started / completed / failed, OSV generated,
  CSAF generated, Git commit, Git push, Git push failed.
- Notification preferences changed.
- GHSA: metadata fetched, linked advisory created, CVE push
  requested / succeeded / failed, CVE conflict detected, sync run
  started / finished, installation registered / suspended / removed,
  webhook received / rejected.
- PMI repo mirror synced.
- Triage: triage submitted, promoted, dismissed (legacy
  `report.*` actions remain in the enum read-only for historical
  rows but are not emitted by new code).
- Authentication: login, logout, failed login, step-up re-auth
  completed.
- Notification delivery: one `notification.sent` row per recipient.
- User governance: account banned / unbanned.

Each row carries the actor (nullable for system actions), the action
type, the affected advisory (when applicable), an optional
`comment_id`, structured `previous_value` / `new_value` deltas, a
machine-readable `metadata` JSON blob, and the requesting IP and
User-Agent when the entry originated from an HTTP request
([INV-AUDIT-4](./invariant.md#inv-audit-4)).

All user/CI-supplied strings are funnelled through
`audit.services.redact_secrets` before persistence
([INV-AUDIT-2](./invariant.md#inv-audit-2)). The audit table is
append-only at both layers (model `save`/`delete` guards plus
Postgres triggers; [INV-AUDIT-1](./invariant.md#inv-audit-1),
[INV-IMPL-2](./invariant.md#inv-impl-2)).

Ephemeral events — advisory views, the auth events, notification
deliveries, and GHSA/PMI machine chatter — are routed to the
partitioned `AccessLogEntry` table instead of the durable ledger;
they are retention-bounded (default 90 days) and browsable by admins
at `/admin/access-log/`
([INV-AUDIT-5](./invariant.md#inv-audit-5)).

### 4.6 Access management

Owners (project security team or global admins) may grant access on
an advisory to:

- a Django user, by primary key (resolved via the existing user
  table); or
- a Django group; or
- an email address that has no user yet — this creates a
  `PendingInvitation` and queues an invitation email.

Permission levels available to grants and invitations are `viewer`
and `collaborator`; `owner` is never grantable
([INV-ACCESS-4](./invariant.md#inv-access-4)). A grant is unique per
`(advisory, principal_type, principal_id)`; re-granting the same
principal updates the existing row in place.

Invitations carry an opaque token and an expiry (default 14 days).
Redemption matches the authenticated user's email
case-insensitively ([INV-ACCESS-2](./invariant.md#inv-access-2)) and
rejects expired rows ([INV-ACCESS-3](./invariant.md#inv-access-3)).
An invitation cannot be redeemed by a different email.

Every grant create / update / revoke and every invitation create /
redeem / revoke emits an audit entry
([INV-ACCESS-5](./invariant.md#inv-access-5)).

A project change on an advisory stamps `access_review_required_at`,
surfacing a banner that prompts the owner to prune grants that no
longer apply.

### 4.7 Notifications

Each user has a single `NotificationPreference` row carrying global
defaults; per-advisory overrides live in
`AdvisoryNotificationPreference` (sparse — only fields the user has
explicitly customised). The events that can produce email are:

| Event | Per-user toggle | Per-advisory override |
|---|---|---|
| Advisory created in a project where you are on the security team | `on_advisory_created` | — (global only) |
| Advisory you have access to is submitted for review | `on_advisory_submitted_for_review` | yes |
| Advisory you have access to is published | `on_advisory_published` | yes |
| Publication export status (success or failure) for an advisory you have access to | `on_publication_export_status` | yes |
| New comment on an advisory you have access to | `comments_level` ∈ `{all, mentioned}` | yes (incl. `inherit` sentinel) |
| You are `@-mentioned` on a comment | — (always delivered to comment-visible users) | — |
| Triage-flow events (`advisory_triage_submitted/promoted/dismissed/reassigned/flagged_for_routing/routing_flag_cleared`) | gated by project security-team membership; admins receive the `flagged_for_routing` events regardless of project | — |
| You receive an invitation to an advisory | always delivered | — |

`comments_level` has no `none` option — mentions are always delivered
to users who can see the comment, and "no comments at all" would
let an owner suppress mentions on their own advisory.

Recipient lists are recomputed at *send* time via
`notifications.recipients.filter_for_event`; a user whose access was
revoked between enqueue and send drops from the queue
([INV-PRIVACY-2](./invariant.md#inv-privacy-2)). For internal
comments, users who cannot see internal comments are dropped even
when mentioned. Body templates are deliberately sparse — recipients
see what changed and a link back into the authenticated app, never
private advisory content directly in the email.

When `PMI_ROSTER_SYNC_ENABLED` is on, the security-team roster sync
pre-provisions notification-only shadow users so triage events and
`@team` mentions also reach security-team members who have never
logged in ([INV-OIDC-5](./invariant.md#inv-oidc-5),
[INV-ROSTER-1](./invariant.md#inv-roster-1)).

Every delivered email also lands in the recipient's in-app inbox
(`Notification` rows, §3), where entries are marked read explicitly
or by visiting the linked page; each delivery is recorded in the
access log (`notification.sent`).

Changes to a user's `NotificationPreference` are audited
(`NOTIFICATION_PREFS_CHANGED`).

### 4.8 Advisory workflow actions

The three workflow actions available from an advisory's edit view
(when allowed) are:

- **Request a CVE.** Opens a queued `CveRequestTask` for the global
  admin team. Owner-only; refused when the advisory already has an
  `assigned_cve_id`, an open task, or `cve_requests_banned=True`. The
  admin team transitions it to `reserved` (carrying the chosen
  `cve_id`), `rejected` (with non-empty notes and optionally setting
  `cve_requests_banned`), or implicitly `cancelled` on dismissal.
- **Submit for review.** Pins the current latest `AdvisoryVersion`
  into a new `ReviewTask`, sets `review_status=submitted`, and freezes
  edits for non-admins. Owner-only — admins are the reviewers and
  cannot submit. Reviewers (admins) approve, request changes, or
  revoke an existing approval; the submitter may withdraw.
- **Publish.** Owner-only; for projects where
  `is_mature_publisher=False`, the security team may only publish
  while `review_status=approved` (or hand off to an admin). For
  mature publishers, drafts can be published directly. Publication is
  always refused while `review_status=submitted`
  ([INV-PERM-3](./invariant.md#inv-perm-3)).

Dismissing a draft auto-cancels any open CVE request and, when an
`assigned_cve_id` is present (admin-only path), creates an
`OrphanCve` row so the admin team marks it rejected at cve.org.

### 4.9 Publication

Publication is the only path to `state=published`. The complete
sequence is documented in
[`advisory-lifecycle.md` §8](./advisory-lifecycle.md#8-publication-sequence-diagram);
the requirements are:

1. The publish action creates a `PublicationTask` pinning the current
   latest `AdvisoryVersion`. A second attempt while one is queued or
   running raises `PublicationInProgress`
   ([INV-CONCURRENCY-1](./invariant.md#inv-concurrency-1)). The
   Celery task is enqueued via `transaction.on_commit` so a
   rolled-back caller never leaves a stray queued task
   ([INV-PUB-5](./invariant.md#inv-pub-5)).
2. For GHSA-linked advisories the worker first refreshes metadata
   from GitHub; if the refresh appends a new version, the task is
   re-pinned to the latest version before generation.
3. OSV and CSAF documents are built from `task.version.payload`
   ([INV-VERSION-3](./invariant.md#inv-version-3)) and validated
   against the vendored JSON schemas in `publication/schemas/`
   ([INV-PUB-6](./invariant.md#inv-pub-6)). Each validated document
   is persisted to a `PublicationArtifact` row (one per kind per
   task); the dashboard's preview screens read these rows.
4. The publication repository is cloned into a fresh
   `tempfile.TemporaryDirectory()` per attempt
   ([INV-PUB-1](./invariant.md#inv-pub-1)), shallow
   ([INV-PUB-3](./invariant.md#inv-pub-3)). Files land at the
   configured templates (default `osv/{year}/{advisory_id}.json` and
   `csaf/{year}/{advisory_id}.json`, bucketed by the advisory's
   first-publication year).
5. The commit is created with the configured author (no GPG signing
   — the deploy key/token is the trust signal) and pushed to the
   configured branch.
6. **Only on a clean push** the worker, inside the same
   `transaction.atomic` block guarded by `select_for_update`
   ([INV-PUB-4](./invariant.md#inv-pub-4)): sets `state=published`,
   stamps `published_at` if previously null, clears
   `republish_required`, finalises the task with the commit SHA, and
   records `ADVISORY_PUBLISHED`, `PUBLICATION_GIT_COMMIT`,
   `PUBLICATION_GIT_PUSH`, and `PUBLICATION_EXPORT_COMPLETED`.
7. On any failure (schema validation, clone, write, commit, push)
   the advisory's state is unchanged
   ([INV-LIFECYCLE-3](./invariant.md#inv-lifecycle-3)), the task is
   marked `failed` with a redacted `last_error`, and
   `PUBLICATION_EXPORT_FAILED` (or `PUBLICATION_GIT_PUSH_FAILED` for
   push-time errors) is emitted.

Re-publication runs the same pipeline against the current latest
`AdvisoryVersion`; deterministic paths mean a re-publish appears in
the publication repo as a new commit on the same path, while every
prior `AdvisoryVersion` and `PublicationArtifact` remains immutable.

Two authentication modes are supported, mutually exclusive
([INV-PUB-2](./invariant.md#inv-pub-2)):

- `ssh` — git's `GIT_SSH` hook is pointed at a per-call generated
  wrapper that execs ssh with `IdentitiesOnly=yes`, `BatchMode=yes`,
  `StrictHostKeyChecking=accept-new`; the wrapper lives in the call's
  scratch directory and vanishes with it
  ([INV-SECRET-2](./invariant.md#inv-secret-2)).
- `token` — the HTTPS URL is rewritten with
  `https://x-access-token:$PUB_REPO_TOKEN@…` for the duration of the
  clone; the token never appears in repo state, audit metadata, task
  rows, or notification bodies
  ([INV-SECRET-1](./invariant.md#inv-secret-1),
  [INV-SECRET-2](./invariant.md#inv-secret-2),
  [INV-SECRET-3](./invariant.md#inv-secret-3)).

### 4.10 GHSA integration

The integration's high-level shape:

- AdvisoryHub authenticates to GitHub as a registered **GitHub App**
  (`repository_security_advisories: read & write` plus the default
  `metadata: read`). The installation is recorded in
  `GitHubAppInstallation` and re-discovered via the
  `discover_github_installations` management command or the inbound
  `installation.created` webhook.
- The **PMI repo mirror** (`ProjectGitHubRepository`) is refreshed by
  the Celery beat task `ghsa.tasks.run_pmi_repo_sync`, which runs
  every `PMI_SYNC_INTERVAL_HOURS` hours and is the authoritative
  source for which `(owner, name)` repos belong to which project.
- **GHSA discovery** happens on-demand: admins can sync one project
  or all projects from the admin console; project security-team
  members can sync their own project. Discovery creates new
  `Advisory(kind=ghsa_linked)` rows (or updates existing ones)
  whose `ghsa_id` is uniquely mapped
  ([INV-ID-2](./invariant.md#inv-id-2)).
- **Per-advisory sync** refreshes metadata from GitHub for a single
  advisory; updates that change payload-visible fields append a new
  `AdvisoryVersion`, updates that are heartbeats (no change) only
  refresh `ghsa_metadata_synced_at`.
- **CVE push.** When an admin reserves an EF-assigned CVE on a
  GHSA-linked advisory, AdvisoryHub queues a `GhsaCvePushTask` that
  writes the CVE back to the upstream GHSA. Push success / failure /
  conflict (when GitHub already has a different CVE for the same
  GHSA) is audited and surfaced.
- **Webhooks.** Inbound webhook deliveries are HMAC-verified against
  `GITHUB_APP_WEBHOOK_SECRET` and deduplicated by delivery ID.
  Suspended or removed installations have their access immediately
  revoked.

The GHSA feature is gated behind the `GHSA_FEATURE_ENABLED` flag.

### 4.11 Admin console

The admin console at `/admin/` (Django admin proper lives at
`/django-admin/`) is the global security team's workspace. Sidebar
sections:

- **Inbox** (`/admin/`) — the unified action feed: triage queue,
  pending reviews, awaiting CVE assignment, failed publications,
  recent audit activity. Chip-driven `?category=<slug>` filter.
  There is no dedicated Reviews section: open `ReviewTask`s surface
  here as an Inbox category, and the approve / request-changes
  decision UI lives on the advisory page itself.
- **CVE Assignment** (`/admin/cves/`) — open `CveRequestTask`s and
  per-task transition actions; modal flow for the rejection note.
  Also surfaces `OrphanCve` rows for "mark rejected at cve.org".
- **Publication** (`/admin/publications/`) — publication task
  history, including failed exports, with retry, the redacted
  `last_error`, and OSV / CSAF previews from the stored
  `PublicationArtifact` content.
- **Projects** (`/admin/projects/`) — CRUD on `Project` rows
  (security team, mature-publisher flag, PMI sync status).
- **Groups** (`/admin/groups/`) — read-only directory of the
  mirrored OIDC groups: members, projects secured, and per-advisory
  group grants.
- **Audit** (`/admin/audit/`) — filterable read of the audit log.
- **Access log** (`/admin/access-log/`) — filtered read of the
  ephemeral access-log events (advisory views, auth events,
  notification deliveries), retention-bounded
  ([INV-AUDIT-5](./invariant.md#inv-audit-5)).
- **Users** (`/admin/users/`) — read-only directory of accounts
  (groups, per-advisory grants, notification settings) with admin
  ban / unban and the `forget` retention action; a banned account is
  denied login and dropped mid-session
  ([INV-AUTH-8](./invariant.md#inv-auth-8)).
- **Maintenance** (`/admin/maintenance/`) — single-button
  maintenance-mode toggle with an admin-configurable banner message.
  While on, only global admins may mutate state; every other user's
  writes are paused server-side by
  `common.middleware.MaintenanceModeMiddleware`
  ([INV-MAINT-1](./invariant.md#inv-maint-1)).

Every admin-console view is wrapped with `@admin_required`, which is
`can_review` (global admin only) — see
[`permissions.md` §9](./permissions.md#9-enforcement-surfaces).

### 4.12 Internal JSON API

The API at `/api/` exposes the same actions as the HTMX views for
script / integration use. The surface is intentionally small and
covers:

- Advisories: list + detail (filtered by `can_view`); patch detail
  (gated by `can_edit`).
- Comments: list + create for a given advisory.
- Access grants: list, create, update, revoke.
- Publication: read task status, start a publish, retry a failed
  task, preview the stored OSV or CSAF artifact.
- Dashboard transitions: CVE-task transition, review decision.

The complete enforcement map is in
[`permissions.md` §9](./permissions.md#9-enforcement-surfaces). Every
endpoint re-evaluates the predicate from `advisories/permissions.py`
that the corresponding HTML view does; list endpoints filter their
querysets through `can_view`.

### 4.13 Duplicate detection (similarity)

Off by default; enabling `SIMILARITY_CHECK_ENABLED` is the explicit
consent for advisory content to leave the deployment for the
configured LLM provider ([INV-SIM-2](./invariant.md#inv-sim-2)).
When enabled:

- Every advisory-creation path (public intake, manual creation, GHSA
  import) enqueues a background `SimilarityCheck`; owners can re-run
  the check on demand from the advisory page.
- A Postgres prefilter (trigram similarity over summary/details plus
  exact alias / CVE / GHSA-id and affected-package overlap) selects
  up to `SIMILARITY_CANDIDATE_LIMIT` same-project candidates. The
  pipeline then spends at most two LLM calls per check regardless of
  corpus size: one to fingerprint the new report (cached in
  `AdvisoryFingerprint`, keyed on a content hash) and one to judge
  all candidates.
- The top five matches scoring at least `SIMILARITY_MIN_CONFIDENCE`
  are stored with a 0–100 confidence and a one-line rationale.
- Results (including the in-progress state) are visible to owners
  only — global admins and the project security team — in a polling
  panel on the advisory page; collaborators and viewers never see
  the surface ([INV-SIM-1](./invariant.md#inv-sim-1)).
- Checks judge the pinned `AdvisoryVersion` payload, never live form
  data ([INV-SIM-4](./invariant.md#inv-sim-4)); provider errors are
  redacted before persistence
  ([INV-SIM-3](./invariant.md#inv-sim-3)).
- The provider client is a thin, SDK-free abstraction: the Anthropic
  Messages API or any OpenAI-compatible Chat Completions endpoint
  (including local servers — the on-prem option for embargoed
  content).

---

## 5. Authorization summary

Three roles only, ranked `viewer < collaborator < owner`
([INV-AUTH-2](./invariant.md#inv-auth-2)). Resolution order:

1. Anonymous → no access.
2. Global admin (member of `OIDC_ADMIN_GROUP`) → owner everywhere.
3. Project security-team member → owner on that project's
   advisories.
4. Highest matching `AdvisoryAccessGrant` (direct user grant or via
   a group the user belongs to) → `collaborator` or `viewer`
   ([INV-AUTH-4](./invariant.md#inv-auth-4)).
5. Otherwise → no access.

Owner is structural (admin or project membership) and never
grantable ([INV-AUTH-3](./invariant.md#inv-auth-3),
[INV-ACCESS-4](./invariant.md#inv-access-4)). The capability matrix
and per-state overrides (triage, review-submitted, published,
dismissed) are in [`permissions.md` §5 and §6](./permissions.md#5-capability-matrix).

**Step-up authentication.** Publishing and connecting/modifying the
GitHub App require a recent OIDC re-authentication
(`step_up_auth_at` within `STEP_UP_MAX_AGE_SECONDS`, default 300 s),
gated by `accounts.step_up.require_step_up_or_redirect`. The check is
session-scoped and is set only when the IdP returned from a
`prompt=login&max_age=0` request; an ordinary sign-in does not
satisfy it. The mechanism is disabled by default in `test` settings
and can be turned off in dev via `STEP_UP_REQUIRED=False`. See
[`permissions.md` §8](./permissions.md#8-step-up-authentication).

**Mature publisher.** A boolean on the `Project` row, flippable by
admins from the admin console
([INV-PERM-2](./invariant.md#inv-perm-2)). When true, the project's
security team may publish drafts without `review_status=approved`,
subject only to the universal "no publish while review is submitted"
gate ([INV-PERM-1](./invariant.md#inv-perm-1),
[INV-PERM-3](./invariant.md#inv-perm-3)).

---

## 6. Use cases

### 6.1 Anonymous triage submission

1. An external researcher visits `/report/`.
2. They pick a project from the autocomplete (or pick "I don't
   know", which maps to the `unsorted` sentinel) and fill summary +
   details in markdown.
3. They submit. The honeypot field is empty (real user); the form
   passes the per-IP rate limit; hCaptcha, if configured, validates.
4. `submit_triage_report` creates an `Advisory(state=triage)` + an
   `AdvisoryIntakeMetadata` row carrying the submitting IP and
   User-Agent. Because the project is `unsorted`,
   `needs_admin_routing` is set automatically.
5. An audit row `ADVISORY_TRIAGE_SUBMITTED` is written; an
   `advisory_triage_submitted` notification is queued (admin team for
   `unsorted`, project security team otherwise).
6. The reporter is redirected to the same thank-you page that a
   honeypot trip would have produced.
7. An admin opens the Inbox in the admin console, reads the report,
   either reassigns the project (`reassign_triage_project`) to the
   correct project — at which point that project's security team
   becomes the owner — and then promotes it
   (`promote_triage_to_draft`), or dismisses it (`dismiss_triage`)
   with a non-empty reason.
8. On promotion the same advisory row continues forward as
   `state=draft`; the PK, public id, and audit history are preserved
   ([INV-LIFECYCLE-5](./invariant.md#inv-lifecycle-5)).

### 6.2 Draft → review → publish (non-mature project)

1. A project security-team member opens "New advisory" for their
   project. The advisory is created in `state=draft`; v1 is seeded
   automatically.
2. They fill in summary, details, affected packages and ranges,
   severity, references, credits. Saving appends `AdvisoryVersion`
   v2 with the payload snapshot.
3. They open "Submit for review". A `ReviewTask` is opened pinning
   v2; `review_status` flips to `submitted`. The advisory becomes
   non-editable for non-admins until the review concludes.
4. An admin reviewer opens the review action on the advisory and
   approves. `review_status` becomes `approved`,
   `ADVISORY_REVIEW_APPROVED` is audited.
5. The team member clicks "Publish". The publish view checks
   `can_publish` (owner, approved review, not dismissed) and asks
   for a step-up re-authentication if stale. A `PublicationTask` is
   created pinning v2 (still latest); a Celery task is enqueued via
   `transaction.on_commit`.
6. The worker builds OSV and CSAF from v2's payload, validates each
   against the vendored schemas, persists `PublicationArtifact` rows,
   clones the publication repo into a fresh `TemporaryDirectory`,
   writes both files at the configured paths, commits, and pushes.
7. On a clean push, the worker (inside `transaction.atomic` +
   `select_for_update`) flips `state` to `published`, stamps
   `published_at`, clears `republish_required`, finalises the task
   with the commit SHA, and emits `ADVISORY_PUBLISHED`,
   `PUBLICATION_GIT_COMMIT`, `PUBLICATION_GIT_PUSH`,
   `PUBLICATION_EXPORT_COMPLETED`.
8. Watchers receive the `advisory_published` notification.

### 6.3 Mature publisher direct publish

Same as §6.2 but skipping steps 3–4: the project carries
`is_mature_publisher=True`, so the team member publishes the draft
directly. The "Publish" action remains gated by step-up and by
"no publish while a review is submitted", but no admin-side approval
is required.

### 6.4 Re-publish after an edit

1. A published advisory is opened by the project security team. Edit
   appends an `AdvisoryVersion`, sets `republish_required=True`, and
   if the team is non-admin and a previous review was approved,
   resets `review_status` to `none`
   ([INV-REVIEW-4](./invariant.md#inv-review-4)).
2. The advisory page's "Publish" button now reads "Re-publish".
3. Re-publishing runs the full pipeline against the new latest
   version. A new `PublicationTask` row is created; OSV + CSAF
   regenerated; a new commit appears at the same file path; prior
   `AdvisoryVersion` and `PublicationArtifact` rows remain
   immutable.
4. `state` is still `published`; only `modified_at`, `published_at`
   (left as-is — it is "first published") and the task / artifact
   chain reflect the re-publish.

### 6.5 Dismiss a draft with an open CVE request

1. A project security team owner opens the draft and clicks
   "Dismiss" with a non-empty `dismissed_reason`. The owner does not
   hold an `assigned_cve_id`, so the dismissal is allowed for them
   (admins may dismiss even with an assigned CVE).
2. Inside the dismiss service: `state=dismissed`,
   `ADVISORY_DISMISSED` audited.
3. `cancel_open_cve_request` runs: the queued `CveRequestTask` flips
   to `cancelled`, `CVE_REQUEST_CANCELLED` is audited.
4. If the advisory had ever carried an `assigned_cve_id` (admin-only
   scenario), `unassign_cve` would have created an `OrphanCve` row
   for the admin team to mark rejected at cve.org.

### 6.6 GHSA-linked advisory: link → sync → push EF CVE → publish

1. An admin runs the org-wide GHSA sync. New GHSAs surface as
   `Advisory(kind=ghsa_linked)` rows in `state=draft`, with
   `ghsa_id`, `ghsa_owner`, `ghsa_repo` populated, OSV-content fields
   read-only and sourced from GHSA's payload. v1 is seeded; the
   first sync may append v2 with refreshed content.
2. The admin (or project security team) requests a CVE for the
   advisory through the normal flow; the admin team transitions the
   `CveRequestTask` to `reserved` with the EF-assigned CVE id.
3. `assigned_cve_id` is set; because the advisory is GHSA-linked
   AdvisoryHub queues a `GhsaCvePushTask` that writes the CVE back
   to the upstream GHSA. Success / failure / conflict is recorded
   (`GHSA_CVE_PUSH_SUCCEEDED` / `_FAILED` / `_CONFLICT_DETECTED`).
4. When the upstream GHSA is published and the team is ready, they
   click "Publish". The publish service first calls
   `ghsa.services.refresh_for_publish` to pull the latest GHSA
   metadata; if anything changed, a new `AdvisoryVersion` is
   appended. The publication task pins the (possibly new) latest
   version and runs the standard OSV + CSAF + Git pipeline.

### 6.7 Access grant via group + invitation redemption

1. An owner opens the access page on an advisory.
2. They grant `collaborator` to a Django group that mirrors an IdP
   group of external contributors. The grant row is unique on
   `(advisory, group, group_id)`; an existing grant for the same
   group updates in place. `ACCESS_GRANTED` is audited.
3. They invite a new external collaborator by email. An invitation
   email is queued with a single-use token; the
   `PendingInvitation` row carries the target `permission`, the
   token, and a 14-day expiry. `INVITATION_CREATED` is audited.
4. The invitee signs in via OIDC; their email matches the
   invitation case-insensitively. `redeem_invitations_for_user`
   creates the grant, stamps `redeemed_at` / `redeemed_by`, and
   emits `INVITATION_REDEEMED`. From this point the user holds the
   granted `collaborator` rank on the advisory; group membership in
   the IdP can layer further grants on top.

### 6.8 Comment with @-mention

1. A collaborator opens the advisory and posts a public comment
   mentioning `@alice` and `@bob@example.org`.
2. The markdown is rendered through the nh3 allowlist and saved
   to `AdvisoryComment.body`; `CommentVersion` v1 carries the same
   body; `COMMENT_CREATED` is audited.
3. `notifications.tasks.send_comment_email` is queued. At send time
   recipients are recomputed: each mentioned user is checked against
   the per-advisory access list (and against comment visibility for
   internal comments); the per-advisory and per-user
   `comments_level` decides whether unmentioned watchers also get an
   email.
4. Mentioned recipients receive a `comment_mention` email;
   unmentioned recipients get a `comment` email; each user receives
   at most one email per comment.
5. Alice edits the comment to fix a typo. A new `CommentVersion`
   row is written; the visible `body` is updated; `edited_at` is
   stamped; `COMMENT_EDITED` is audited.

---

## 7. Non-functional requirements

### 7.1 Security

- Authorization is enforced server-side on every view, every API
  endpoint, and every Celery task
  ([INV-AUTH-1](./invariant.md#inv-auth-1)). Templates are render-only
  and never make access decisions.
- The IdP is the authority for group membership; AdvisoryHub mirrors
  it on every login and never trusts client-submitted group data
  ([INV-OIDC-1](./invariant.md#inv-oidc-1),
  [INV-OIDC-2](./invariant.md#inv-oidc-2)).
- Owner is structural; the grant API rejects `permission="owner"`
  ([INV-AUTH-3](./invariant.md#inv-auth-3),
  [INV-ACCESS-4](./invariant.md#inv-access-4)).
- CSRF protection is enabled via `CsrfViewMiddleware` on every
  state-changing endpoint; the public intake `/report/` form
  inherits the same protection (the JSON project picker is GET-only
  and cache-controlled).
- Markdown bodies (advisory `details`, comments) are sanitised at
  render time through a strict nh3 allowlist; rendered HTML is
  never persisted.
- Step-up authentication gates publication and GitHub App
  configuration.
- Cookies are secure in production (`SESSION_COOKIE_SECURE`,
  `CSRF_COOKIE_SECURE`), `X_FRAME_OPTIONS=DENY`, content-type
  sniffing is disabled.
- A nonce-based `script-src 'strict-dynamic'` Content-Security-Policy
  (django-csp) is **enforced by default**; `style-src 'self'`
  additionally forbids inline styles, and a fixed `Permissions-Policy`
  is emitted alongside. `CSP_REPORT_ONLY=True` falls back to
  Report-Only while diagnosing a violation.
- Secrets — Git tokens, SSH key paths, GitHub App private keys,
  hCaptcha keys, OIDC client secrets — are never persisted into
  audit metadata, task error strings, notification bodies, or
  artifact rows
  ([INV-SECRET-1](./invariant.md#inv-secret-1),
  [INV-SECRET-2](./invariant.md#inv-secret-2),
  [INV-SECRET-3](./invariant.md#inv-secret-3)).

### 7.2 Privacy

- Inside AdvisoryHub, "published" grants no implicit read access:
  every advisory remains gated by the same explicit grants as a
  draft ([INV-AUTH-7](./invariant.md#inv-auth-7)).
- List endpoints, filters, and search totals scope to advisories the
  caller can see — counts never leak the existence of inaccessible
  rows ([INV-PRIVACY-1](./invariant.md#inv-privacy-1)).
- Notification recipients are recomputed at send time so revoked
  grants drop from the queue
  ([INV-PRIVACY-2](./invariant.md#inv-privacy-2)).
- The triage form has no reporter-email field; anonymous reports
  cannot later be re-associated by claiming the email
  ([INV-INTAKE-2](./invariant.md#inv-intake-2)).
- Intake-only PII (submitter IP, User-Agent, display name) lives on
  the `AdvisoryIntakeMetadata` sidecar and can be cleared via the
  `forget_user` retention command without removing the advisory.
- Other users' email addresses are owner-only: collaborators and
  viewers see display names, with the email rendered masked
  (`a•••@example.org`) on every surface — rendered pages, the
  `@`-mention autocomplete, and the JSON API. A user always sees
  their own email
  ([INV-PRIVACY-4](./invariant.md#inv-privacy-4)).

### 7.3 Auditability

- Every governance action recorded in `Action` is audited exactly
  once at the moment it succeeds
  ([INV-AUDIT-3](./invariant.md#inv-audit-3)).
- Audit history is append-only at both layers (model guard +
  Postgres trigger); deleting it requires a follow-up migration that
  itself appears in `git log`
  ([INV-AUDIT-1](./invariant.md#inv-audit-1),
  [INV-IMPL-2](./invariant.md#inv-impl-2)).
- Web-originated entries capture IP and User-Agent
  ([INV-AUDIT-4](./invariant.md#inv-audit-4)).
- Audit metadata is redacted at every entry point
  ([INV-AUDIT-2](./invariant.md#inv-audit-2)).

### 7.4 Reliability & concurrency

- The publish service serialises concurrent publishers on the same
  advisory with `select_for_update` and refuses a second attempt
  while one is in flight
  ([INV-CONCURRENCY-1](./invariant.md#inv-concurrency-1)).
- The state flip, task finalisation, `published_at`, and audit
  emissions share a single `transaction.atomic` block
  ([INV-PUB-4](./invariant.md#inv-pub-4)).
- Celery enqueues happen on `transaction.on_commit`, eliminating
  ghost queue entries from rolled-back callers
  ([INV-PUB-5](./invariant.md#inv-pub-5)).
- Each publish attempt clones into a fresh `TemporaryDirectory`
  ([INV-PUB-1](./invariant.md#inv-pub-1)) — no shared mutable
  checkout, no race between concurrent publishes.

### 7.5 Operability

- `/healthz` answers 200 whenever the Django process is up.
- `/readyz` checks the database, the cache, and (when
  `READYZ_INCLUDE_PUB_REPO=True`) the publication remote;
  returns 503 with the failing check names otherwise.
- Logs are single-line JSON to stderr, with a per-request id from
  `common.middleware.RequestIDMiddleware`; the format is switchable
  to plain text via `LOG_FORMAT=plain`.
- Sentry is initialised when `SENTRY_DSN` is set.
- Prometheus metrics are exposed at `/metrics` (django-prometheus
  defaults plus the custom `advisoryhub_publication_*`,
  `advisoryhub_celery_task_*`, and `advisoryhub_backlog` series; the
  worker exports its own series on a separate port). A dev/demo
  Prometheus + Grafana stack (opt-in `observability` compose profile)
  ships example dashboards, alert rules, and documented SLOs
  (availability ≥ 99.5%, p95 latency < 1s, publication success ≥ 90%).
  In production the operator scrapes `/metrics` with their own
  Prometheus — AdvisoryHub ships no production monitoring
  infrastructure of its own.
- Public intake is rate-limited per-IP for anonymous submitters
  and per-user for authenticated ones; the global toggle
  `RATELIMIT_ENABLE` exists for tests and local debugging.
- The retention commands `prune_audit` and `forget_user` handle
  long-term audit hygiene and per-user PII scrubbing respectively;
  each records its own run on the durable ledger (`AUDIT_PRUNED` /
  `USER_FORGOTTEN`).
- A `seed_demo` management command builds the dev fixture data
  used by the docker-compose dev environment.

### 7.6 Internationalisation

The UI carries English and French locales (`LANGUAGES = [("en", …),
("fr", …)]`) with locale-aware middleware between sessions and
`CommonMiddleware`. Locale files live under `locale/`.

---

## 8. Cross-reference index

- [`invariant.md`](./invariant.md) — load-bearing rules, stable IDs.
- [`advisory-lifecycle.md`](./advisory-lifecycle.md) — state diagrams,
  transition tables, publication sequence diagram.
- [`permissions.md`](./permissions.md) — actors, roles, full
  capability matrix, enforcement surfaces.
- [`architecture.md`](./architecture.md) — technology stack,
  internal structure, operations, testing.
- [`../../CLAUDE.md`](https://github.com/mbarbero/advisoryhub/blob/main/CLAUDE.md) — agent-facing operational
  notes (app layout, common commands, persistence rules).
- [`../../README.md`](https://github.com/mbarbero/advisoryhub/blob/main/README.md) — setup instructions.
