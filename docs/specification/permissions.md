# Permission Model

This document specifies the authorization model of AdvisoryHub: who the
**actors** are, what **roles** they can hold, and what **actions** each role
is allowed to take. It is a companion to [`invariant.md`](./invariant.md);
where a rule has a stable invariant ID, this document references it by ID
(`INV-XYZ-N`) rather than restating the reasoning. Every fact stated here
appears in exactly one place — the capability matrix or the state-conditioned
overrides, never both.

The single source of truth for the executable predicates is
`advisories/permissions.py`. This document tracks that file's intent; if the
two ever disagree, the code wins and this document is wrong.

---

## 1. Purpose & scope

AdvisoryHub is the **authoring** system for security advisories. This document
covers authorization on its authoring surface: the web UI, the JSON API, the
public intake endpoint, the admin console, and the Celery workers.

It does **not** cover the public surface where end users read published
advisories — that surface is a separate static site rendered from the
publication Git repository, with its own (open) access policy. A published
advisory inside AdvisoryHub remains visible only to the same people who could
see it as a draft ([INV-AUTH-7]).

---

## 2. Identity sources

A user is identified by **OIDC login** through `mozilla-django-oidc`, backed
by `accounts.auth.AdvisoryHubOIDCBackend`. Authentication and group
membership both flow from the IdP; AdvisoryHub stores a mirror, never the
authority.

- **User record.** First login creates a Django `User`; subsequent logins
  refresh email and display fields.
- **Groups.** `sync_groups_from_claims` replaces `user.groups` from the
  configured OIDC claim on every login — one-way sync, no caching across
  sessions ([INV-OIDC-1]). Claim values are filtered to SPN form so the
  `Group` table stays clean ([INV-OIDC-4]).
- **Admin flags.** `is_staff` and `is_superuser` are set equal to
  membership in `OIDC_ADMIN_GROUP` on every login; demotion in the IdP
  removes Django admin access on the next login ([INV-OIDC-3]).
- **Trust boundary.** Authorization predicates always read `user.groups`
  (the DB mirror); request bodies, headers, or form fields naming a group
  are ignored ([INV-OIDC-2]).

There is no local password store and no local group editor: revocation
happens in the IdP and propagates at next login.

- **Ban (local override).** `is_active=False` is the one app-side override of
  IdP-mediated authority: an admin can ban an account from the admin console
  to deny login and drop its live session immediately, rather than wait for an
  IdP group change to propagate at next login ([INV-AUTH-8]). It is reversible
  (unban) and audited at both ends. (A Celery task already queued under a
  banned actor still re-checks group membership, not `is_active` — the same
  next-login lag as an IdP demotion.)

---

## 3. Actors

| Actor | How identified | Default authority |
|---|---|---|
| **Anonymous web client** | No session | Submit a public triage report (`POST /report/`) and follow the OIDC redirect. Nothing else. |
| **Authenticated user** | OIDC session | No role on any advisory by default; sees only advisories they have an explicit grant for. |
| **Triage reporter (authenticated)** | OIDC session at submission time | Auto-granted `viewer` on the advisory they filed ([INV-INTAKE-3]). |
| **Triage reporter (anonymous)** | None retained | No link is recorded; the report cannot later be claimed ([INV-INTAKE-2]). |
| **Project security-team member** | Member of `Project.security_team` (a Django `Group`) | Derived `owner` on every advisory under that project. |
| **Shadow roster member (pre-login)** | `User.is_provisioned=True`, linked to an active `SecurityTeamRosterEntry` | **No authority at all.** Notification-only: reachable by their project's default notifications/`@team` mentions; not a member of any group; cannot act. Promoted to a real user on first login ([INV-OIDC-5], [INV-ROSTER-1]). |
| **Global admin / reviewer** | Member of `OIDC_ADMIN_GROUP` | Derived `owner` on every advisory and exclusive reviewer; sole holder of CNA-side and integration-admin powers. |
| **Celery worker** | Runs publication / notification / GHSA / CVE tasks | No ambient authority — every task acts on behalf of a stored `created_by` user and re-checks the relevant predicate at execution time. |

"Reviewer" is not a separate role: it is exactly the global-admin actor
acting on a `ReviewTask`. The only place "reviewer" appears as a distinct
column in this document is the capability matrix's admin-only rows.

---

## 4. Roles & resolution

There are exactly three roles ([INV-AUTH-2]): `viewer`, `collaborator`,
`owner`, ranked in that order.

**Resolution algorithm** (`advisories.permissions.resolved_permission`):

1. Anonymous → no access.
2. Global admin (`OIDC_ADMIN_GROUP` member) → `owner`.
3. Project security-team member for `advisory.project` → `owner`.
4. Explicit grant — the highest rank held across all matching
   `AdvisoryAccessGrant` rows (direct user grant or via a group the user
   belongs to) → `collaborator` or `viewer` ([INV-AUTH-4]).
5. Otherwise → no access.

Resolution does **not** consult `advisory.state`: a published advisory is
still gated by the same explicit grants as a draft ([INV-AUTH-7]).

### Why `owner` is structural, not grantable

`owner` is the most privileged role; making it grantable would let any
existing owner escalate themselves or others, defeating the IdP-mediated
admin / security-team gating. `AdvisoryAccessGrant.Permission.choices`
therefore lists only `collaborator` and `viewer`, and the grant service
rejects `permission="owner"` at the API boundary
([INV-AUTH-3], [INV-ACCESS-4]). The only paths to `owner` are admin-group
or project-security-team membership — both managed in the IdP.

### Grants in detail

- A grant is unique per `(advisory, principal_type, principal_id)`
  ([INV-ACCESS-1]); a second grant for the same principal updates the
  existing row in place.
- `principal_type` is `"user"` or `"group"`; group grants apply to every
  current member of the Django `Group` (which itself mirrors an IdP
  group).
- Invitations (`PendingInvitation`) carry an email and a target
  permission. Redemption matches the authenticated user's email
  case-insensitively ([INV-ACCESS-2]) and refuses expired rows
  ([INV-ACCESS-3]; default lifetime 14 days).
- Every create / update / revoke / invite / redeem emits an audit entry
  ([INV-ACCESS-5]).

### Shadow (pre-login) security-team members

To make `@team` mentions and team notifications reach security-team members
who have **never logged in**, a scheduled sync mirrors each project's Eclipse
security team (`projects.services.sync_security_team_roster`, from the
authenticated Eclipse API) into `SecurityTeamRosterEntry` rows and
pre-provisions a *shadow* `User` (`is_provisioned=True`) per member.

A shadow user is **notify-only**: it is not a member of any group, resolves to
no permission, and cannot act. Its sole effect is notification reach — it
receives the security-team member's *default* notification set **for its own
project only** (advisory-created, lifecycle events, triage-queue events, and
`@`-mentions), and is always dropped from internal comments ([INV-ROSTER-1]).
Triage notifications are gated by the global `on_triage_event` preference
(default on), which authenticated members may turn off. On first OIDC login the
shadow is linked by email,
`is_provisioned` clears, and access then comes entirely from the OIDC group
claim ([INV-OIDC-5]) — the roster never grants access.

Because notification emails embed advisory/comment content, this is a
deliberate decision to disclose that content to an email sourced from the
authenticated Eclipse security-team roster before the recipient has logged in.
That trust boundary is the project's own security team (the same audience a
private security mailing list would reach); internal comments stay
collaborator+ only.

---

## 5. Capability matrix

The matrix below is the **only** role-action table in this document. It
states what each role can do *when the advisory is in `state=draft` and
`review_status` is `none` or `changes_requested`* — i.e. the unconstrained
case. The next section lists the overrides that apply in other states.

A user holding multiple roles takes the highest (e.g. an admin who is
also a viewer-by-grant acts as owner).

Symbols: ✓ allowed, ✗ blocked, — not applicable. Footnoted cells have
asymmetries with the same-row entries.

| Action | Viewer | Collaborator | Owner (security team) | Global admin |
|---|---|---|---|---|
| View advisory | ✓ | ✓ | ✓ | ✓ |
| Post public comment | ✓ | ✓ | ✓ | ✓ |
| See internal comments | ✗ | ✓ | ✓ | ✓ |
| Post internal comment | ✗ | ✓ | ✓ | ✓ |
| See other users' email addresses | ✗ ⁷ | ✗ ⁷ | ✓ | ✓ |
| Edit advisory content | ✗ | ✓ | ✓ | ✓ |
| Grant / revoke access | ✗ | ✗ | ✓ | ✓ |
| View duplicate-check results / trigger a re-run | ✗ | ✗ | ✓ ⁸ | ✓ ⁸ |
| Change advisory's project | ✗ | ✗ | ✓ ¹ | ✓ |
| Dismiss advisory | ✗ | ✗ | ✓ ² | ✓ |
| Reopen dismissed advisory | ✗ | ✗ | ✓ ⁶ | ✓ ⁶ |
| Request a CVE | ✗ | ✗ | ✓ ³ | ✓ ³ |
| Submit advisory for review | ✗ | ✗ | ✓ | ✗ ⁴ |
| Approve / request changes on a review | ✗ | ✗ | ✗ | ✓ |
| Withdraw a pending review | ✗ | ✗ | ✓ | ✗ ⁴ |
| Revoke an existing approval | ✗ | ✗ | ✗ | ✓ |
| Publish | ✗ | ✗ | ✓ ⁵ | ✓ |
| Unassign a CVE | ✗ | ✗ | ✗ | ✓ |
| Mark an orphan CVE rejected | — | — | — | ✓ |
| Resolve an orphan CVE reassignment task | — | — | — | ✓ |
| Sync GHSA metadata for one advisory | ✗ | ✗ | ✓ | ✓ |
| Sync GHSA across one project | — | — | ✓ | ✓ |
| Sync GHSA across the org | — | — | ✗ | ✓ |
| Configure the GitHub App | — | — | ✗ | ✓ |
| Retry a failed CVE push | — | — | ✗ | ✓ |
| Browse the triage queue (Admin Console Inbox) | — | — | ✗ | ✓ |
| Submit a public triage report | ✓ (also anonymous) | ✓ | ✓ | ✓ |

Footnotes:

¹ Both the source advisory's owner role **and** security-team membership
on the destination project are required (admins are exempt from the
destination check). Defined by `can_change_project`. This applies to
**native** advisories only: a GHSA-linked advisory's project follows its
source repository in PMI and is never reassigned by hand — it is re-homed
only by the PMI repo sync ([INV-GHSA-1](./invariant.md#inv-ghsa-1)).

² Owner-only **and** the advisory must not currently have an
`assigned_cve_id` (pulling the CVE is a CNA-side action only admins can
take). Admins may dismiss even with an assigned CVE.

³ Owner-only **and** the advisory must not have an open
`CveRequestTask`, an `assigned_cve_id`, or `cve_requests_banned=True`
([INV-CVE-1]).

⁴ Admins are the reviewers and cannot submit or withdraw submissions —
this avoids self-review ([INV-REVIEW-3]).

⁵ Project security-team members may publish only when *either* the
project is marked `is_mature_publisher` *or* the advisory carries
`review_status=approved` (see §7).

⁶ Reopen is the only allowed `state=dismissed` action besides viewing.
The reopened advisory returns to `Advisory.dismissed_from_state`
(`triage` or `draft`); the normal review and publication gates re-engage
from there. There is no direct `dismissed → published` transition
([INV-LIFECYCLE-4]). Defined by `can_reopen`.

⁷ Owner-only PII gate ([INV-PRIVACY-4](./invariant.md#inv-privacy-4)).
Collaborators and viewers see display names only — where a user has no display
name, the email is rendered masked (`a•••@example.org`). A user always sees
their *own* email. This applies to every surface: rendered pages, the
`@`-mention autocomplete, and the JSON API. Defined by `can_see_user_emails`.

⁸ Owner-only because results enumerate other same-project advisories
(ids, confidence, rationale) — exactly the set every owner of the checked
advisory can already see, and more than a per-advisory grantee may see
([INV-SIM-1](./invariant.md#inv-sim-1)). The whole surface 404s while
`SIMILARITY_CHECK_ENABLED` is off ([INV-SIM-2](./invariant.md#inv-sim-2)).
Enforced by `similarity.views` via `resolved_permission == "owner"`.

---

## 6. State-conditioned overrides

The matrix in §5 assumes `state=draft` with `review_status` in
`{none, changes_requested}`. The other states and the review-pending
state add the following restrictions on top of (never in addition to)
the matrix:

- **`triage`.** Only the `owner` row of the matrix applies; collaborator
  and viewer rows are suppressed for *every* action other than `View
  advisory` and `Post public comment`. The reporter's auto-granted
  viewer can therefore read and comment on their report, but cannot
  edit, publish, or request a CVE on it ([INV-AUTH-5]). Internal
  comments still require collaborator+. In addition: `Submit advisory
  for review` and `Publish` are blocked for everyone (advisories must
  be promoted to `draft` first). The triage-specific actions
  `promote_triage_to_draft`, `dismiss_triage`, and
  `flag_for_admin_routing` follow the `owner` column, with the
  asymmetry that admins cannot flag (their queue is the destination).

- **`triage` with `needs_admin_routing=True`.** Further restricted to
  **global admins only** for edit, triage decisions, and clearing the
  flag. Project owners may *flag* a misrouted report (only when not
  already flagged and not on the `unsorted` sentinel project) but may
  not *unflag* it ([INV-AUTH-6], [INV-INTAKE-4]).

- **`review_status=submitted`.** `Edit advisory content` is blocked for
  every role except global admin. `Publish` is blocked for **everyone,
  including admins** — the pending review must be decided or withdrawn
  first ([INV-PERM-3]). `Withdraw a pending review` is the
  submitter-side affordance for non-admin owners; admins decide via
  Approve / Request changes.

- **`published`.** `Dismiss advisory` is blocked (a published row stays
  published; corrections go through Edit + Re-publish). Edits append a
  new `AdvisoryVersion` and set `republish_required=True`, which makes
  the existing matrix-allowed `Publish` action surface a re-publish
  button ([INV-VERSION-1], [INV-REVIEW-4]). Edits that would otherwise
  invalidate an `approved` review reset `review_status` automatically.

- **`dismissed`.** While dismissed, `Publish`, `Submit advisory for
  review`, `Request a CVE`, and `Edit advisory content` are blocked for
  every role. `Reopen dismissed advisory` is the only state-change
  action available; it is owner-gated and returns the advisory to
  `Advisory.dismissed_from_state` ([INV-LIFECYCLE-4]). The advisory
  remains viewable per its grants throughout.

These are the only state overrides. Anything not mentioned here follows
the matrix unchanged.

---

## 7. Mature publisher

A project may be flagged `is_mature_publisher` on its `Project` row
([INV-PERM-2]). When set, the `Publish` matrix entry for the project's
security-team members no longer requires `review_status=approved`: the
team may publish drafts directly, subject only to the universal
"no publish while review is submitted" gate from §6
([INV-PERM-1], [INV-PERM-3]).

Mature-publisher status is **not** an IdP group, an environment
variable, or a per-user flag — it lives on the project row so admins
can flip it from the admin console and the change is auditable.

---

## 8. Step-up authentication

A small set of actions require a **recent re-authentication** in
addition to passing the matrix check. `accounts.step_up.is_step_up_fresh`
gates them against `session["step_up_auth_at"]`; if the timestamp is
missing or older than `STEP_UP_MAX_AGE_SECONDS` (default 300 s), the
view redirects through `require_step_up_or_redirect` for a forced
re-prompt.

The actions currently gated by step-up are:

- **Publish** — `publication/views.py`.
- **Connect or modify the GitHub App** — `ghsa/views.py`.

The whole mechanism is switched off when `STEP_UP_REQUIRED=False`
(default in the `test` settings module so test clients can `force_login`
without an OIDC round-trip).

---

## 9. Enforcement surfaces

Every surface re-checks the same predicates from
`advisories/permissions.py`. Templates only display — they never decide
([INV-AUTH-1]).

| Surface | Module(s) | Enforcement |
|---|---|---|
| Web views | `advisories/views.py`, `access/views.py`, `comments/views.py`, `workflows/views.py`, `publication/views.py`, `ghsa/views.py` | `require_advisory_permission` decorator or `AdvisoryPermissionMixin`; explicit `can_*` calls before each state-changing action. |
| JSON API | `api/views_*.py` | Same `can_*` predicates as the web views (e.g. `can_grant_access`, `can_view`, `can_see_internal_comment`, `can_publish`); list endpoints filter querysets through `can_view`. |
| Admin console | `admin_console/views/*` | All sections wrapped with `@admin_required`, which is `can_review` (global admin only). |
| Duplicate-check panel | `similarity/views.py` | Owner-only (`resolved_permission == "owner"`) on both the HTMX fragment and the re-run POST; the whole surface returns 404 while `SIMILARITY_CHECK_ENABLED` is off ([INV-SIM-1], [INV-SIM-2]). |
| Celery tasks | `publication/tasks.py`, `notifications/tasks.py`, `ghsa/tasks.py`, `workflows/tasks.py` | Re-resolve recipients / actors against the current DB state at task time; notification recipient lists are filtered again at send so revoked grants drop ([INV-PRIVACY-2]). |
| Public intake | `intake/views.py` | No authorization (`can_submit_triage_report` always returns true). Abuse control is the form-layer honeypot ([INV-INTAKE-1]) plus rate limits keyed on anonymous/authenticated (`RATELIMIT_INTAKE_ANON` / `RATELIMIT_INTAKE_USER`). |
| Comment read filtering | `comments/services.py`, `comments/views.py` | `is_internal` is fixed at creation ([INV-COMMENT-1]); visibility is re-checked at *read* and notification *send* time ([INV-COMMENT-2]). |

---

## 10. Audit footprint

Every governance action that this document names emits exactly one
`AuditLogEntry` row at the moment it succeeds ([INV-AUDIT-3]). The
authoritative catalogue of recordable actions is the `Action` enum in
`audit/models.py`; web-originated entries additionally capture the
requesting IP and User-Agent ([INV-AUDIT-4]). The log is append-only
in both the application and database layers ([INV-AUDIT-1]).

For an action to count as "audited" it must reach `audit.services.record`
or `record_from_request` — both funnel every user/CI-supplied string
through `redact_secrets` so tokens, key paths, and bearer URLs never
land in audit metadata ([INV-AUDIT-2], [INV-SECRET-1]).

---

## 11. Out of scope

- **Public anonymous reads.** The website at which published advisories
  are consumed lives in a separate Git repository; its access policy is
  not part of this document. Inside AdvisoryHub, "published" never
  grants implicit read ([INV-AUTH-7]).
- **MITRE CVE assignment.** `workflows.CveRequestTask` is an internal
  queue; AdvisoryHub does not call any external CVE API and does not
  authorize external CNA actions.
- **IdP-side group management.** Group membership is managed in the
  IdP (Kanidm in dev). AdvisoryHub mirrors and reads it, but does not
  let anyone edit it from the application.
