# Permission Model

This document specifies the authorization model of AdvisoryHub: who the
**actors** are, what **roles** they can hold, and what **actions** each role
is allowed to take. It is a companion to [`invariant.md`](./invariant.md);
where a rule has a stable invariant ID, this document references it by ID
(`INV-XYZ-N`) rather than restating the reasoning. Every fact stated here
appears in exactly one place — the capability matrix or the state-conditioned
overrides, never both.

This document is the single source of truth for the authorization model:
the executable predicates in `advisories/permissions.py` and the
enforcement surfaces in §9 must conform to it. If this document and the
code disagree, that is a defect — either the code drifted (fix the code)
or the behavior changed deliberately without a spec update (fix this
document in the same change). Deviating from this document requires
explicit maintainer confirmation *before* implementation.

---

## 1. Purpose & scope

AdvisoryHub is the **authoring** system for security advisories. This document
covers authorization on its authoring surface: the web UI, the JSON API, the
public intake endpoint, the admin console, and the Celery workers.

It does **not** cover the public surface where end users read published
advisories — that surface is a separate static site rendered from the
publication Git repository, with its own (open) access policy. A published
advisory inside AdvisoryHub remains visible only to the same people who could
see it as a draft ([INV-AUTH-7](./invariant.md#inv-auth-7)).

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
  sessions ([INV-OIDC-1](./invariant.md#inv-oidc-1)). Claim values are filtered to SPN form so the
  `Group` table stays clean ([INV-OIDC-4](./invariant.md#inv-oidc-4)).
- **Admin flags.** `is_staff` and `is_superuser` are set equal to
  membership in `OIDC_ADMIN_GROUP` on every login, so demotion in the IdP
  clears both flags on the next login ([INV-OIDC-3](./invariant.md#inv-oidc-3)).
  These flags gate nothing in-app today (Django admin is not mounted; the
  admin console keys off group membership) — the sync is defense-in-depth
  hygiene that keeps the columns honest.
- **Trust boundary.** Authorization predicates always read `user.groups`
  (the DB mirror); request bodies, headers, or form fields naming a group
  are ignored ([INV-OIDC-2](./invariant.md#inv-oidc-2)).

There is no local password store and no local group editor: revocation
happens in the IdP and propagates at next login.

- **Ban (local override).** `is_active=False` is the one app-side override of
  IdP-mediated authority: an admin can ban an account from the admin console
  to deny login and drop its live session immediately, rather than wait for an
  IdP group change to propagate at next login ([INV-AUTH-8](./invariant.md#inv-auth-8)). It is reversible
  (unban) and audited at both ends. (A Celery task already queued under a
  banned actor still re-checks group membership, not `is_active` — the same
  next-login lag as an IdP demotion.)

---

## 3. Actors

| Actor | How identified | Default authority |
|---|---|---|
| **Anonymous web client** | No session | Submit a public triage report (`POST /report/`) and follow the OIDC redirect. Nothing else. |
| **Authenticated user** | OIDC session | No role on any advisory by default; sees only advisories they have an explicit grant for. |
| **Triage reporter (authenticated)** | OIDC session at submission time | Auto-granted `viewer` on the advisory they filed ([INV-INTAKE-3](./invariant.md#inv-intake-3)). |
| **Triage reporter (anonymous)** | None retained | No link is recorded; the report cannot later be claimed ([INV-INTAKE-2](./invariant.md#inv-intake-2)). |
| **Project security-team member** | Member of `Project.security_team` (a Django `Group`) | Derived `owner` on every advisory under that project. |
| **Shadow roster member (pre-login)** | `User.is_provisioned=True`, linked to an active `SecurityTeamRosterEntry` | **No authority at all.** Notification-only: reachable by their project's default notifications/`@team` mentions; not a member of any group; cannot act. Promoted to a real user on first login ([INV-OIDC-5](./invariant.md#inv-oidc-5), [INV-ROSTER-1](./invariant.md#inv-roster-1)). |
| **Global admin / reviewer** | Member of `OIDC_ADMIN_GROUP` | Derived `owner` on every advisory and exclusive reviewer; sole holder of CNA-side and integration-admin powers. |
| **Celery worker** | Runs publication / notification / GHSA / CVE tasks | No ambient authority — every task acts on behalf of a stored `created_by` / `enqueued_by` user. Permission predicates are checked at *enqueue* time (`advisory-lifecycle.md` §3.1 row 7; an operator retry re-runs `can_publish` via `publication.services.retry`); at execution the worker re-validates task state, and notification recipient lists are re-resolved at *send* time ([INV-PRIVACY-2](./invariant.md#inv-privacy-2)). |

"Reviewer" is not a separate role: it is exactly the global-admin actor
acting on a `ReviewTask`. The only place "reviewer" appears as a distinct
column in this document is the capability matrix's admin-only rows.

---

## 4. Roles & resolution

There are exactly three roles ([INV-AUTH-2](./invariant.md#inv-auth-2)): `viewer`, `collaborator`,
`owner`, ranked in that order.

**Resolution algorithm** (`advisories.permissions.resolved_permission`):

1. Anonymous → no access.
2. Global admin (`OIDC_ADMIN_GROUP` member) → `owner`.
3. Project security-team member for `advisory.project` → `owner`.
4. Explicit grant — the highest rank held across all matching
   `AdvisoryAccessGrant` rows (direct user grant or via a group the user
   belongs to) → `collaborator` or `viewer` ([INV-AUTH-4](./invariant.md#inv-auth-4)).
5. Otherwise → no access.

Resolution does **not** consult `advisory.state`: a published advisory is
still gated by the same explicit grants as a draft ([INV-AUTH-7](./invariant.md#inv-auth-7)).

### Why `owner` is structural, not grantable

`owner` is the most privileged role; making it grantable would let any
existing owner escalate themselves or others, defeating the IdP-mediated
admin / security-team gating. `AdvisoryAccessGrant.Permission.choices`
therefore lists only `collaborator` and `viewer`, and the grant service
rejects `permission="owner"` at the API boundary
([INV-AUTH-3](./invariant.md#inv-auth-3), [INV-ACCESS-4](./invariant.md#inv-access-4)). The only paths to `owner` are admin-group
or project-security-team membership — both managed in the IdP.

### Grants in detail

- A grant is unique per `(advisory, principal_type, principal_id)`
  ([INV-ACCESS-1](./invariant.md#inv-access-1)); a second grant for the same principal updates the
  existing row in place.
- `principal_type` is `"user"` or `"group"`; group grants apply to every
  current member of the Django `Group` (which itself mirrors an IdP
  group).
- Invitations (`PendingInvitation`) carry an email and a target
  permission. Redemption matches the authenticated user's email
  case-insensitively ([INV-ACCESS-2](./invariant.md#inv-access-2)) and refuses expired rows
  ([INV-ACCESS-3](./invariant.md#inv-access-3); default lifetime 14 days).
- Every create / update / revoke / invite / redeem emits an audit entry
  ([INV-ACCESS-5](./invariant.md#inv-access-5)).

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
`@`-mentions), and is always dropped from internal comments ([INV-ROSTER-1](./invariant.md#inv-roster-1)).
Triage notifications are gated by the global `on_triage_event` preference
(default on), which authenticated members may turn off. On first OIDC login the
shadow is linked by email,
`is_provisioned` clears, and access then comes entirely from the OIDC group
claim ([INV-OIDC-5](./invariant.md#inv-oidc-5)) — the roster never grants access.

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
| Post comment | ✓ ¹² | ✓ ¹² | ✓ | ✓ |
| See internal comments | ✗ | ✓ | ✓ | ✓ |
| Post internal comment | ✗ | ✓ ¹² | ✓ | ✓ |
| Lock / unlock comments | ✗ | ✗ | ✓ ¹² | ✓ ¹² |
| See other users' email addresses | ✗ ⁷ | ✗ ⁷ | ✓ | ✓ |
| Edit advisory content | ✗ | ✓ | ✓ | ✓ |
| Grant / revoke access | ✗ | ✗ | ✓ | ✓ |
| View duplicate-check results / trigger a re-run | ✗ | ✗ | ✓ ⁸ | ✓ ⁸ |
| Change advisory's project | ✗ | ✗ | ✓ ¹ | ✓ |
| Request reassignment (draft) | ✗ | ✗ | ✓ ⁹ | ✗ ⁹ |
| Withdraw a reassignment request | ✗ | ✗ | ✓ ⁹ | ✓ ⁹ |
| Dismiss advisory | ✗ | ✗ | ✓ ² | ✓ |
| Reopen dismissed advisory | ✗ | ✗ | ✓ ⁶ | ✓ ⁶ |
| Request a CVE | ✗ | ✗ | ✓ ³ | ✓ ³ |
| Submit advisory for review | ✗ | ✗ | ✓ ¹⁰ | ✗ ⁴ |
| Approve / request changes on a review | ✗ | ✗ | ✗ | ✓ ¹⁰ |
| Withdraw a pending review | ✗ | ✗ | ✓ ¹⁰ | ✗ ⁴ |
| Revoke an existing approval | ✗ | ✗ | ✗ | ✓ ¹⁰ |
| Publish | ✗ | ✗ | ✓ ⁵ ¹⁰ | ✓ |
| Withdraw a published advisory | ✗ | ✗ | ✓ ¹¹ | ✓ |
| Request withdrawal of a published advisory | ✗ | ✗ | ✓ ¹¹ | ✗ ¹¹ |
| Approve / cancel a withdrawal request | ✗ | ✗ | ✗ / ✓ ¹¹ | ✓ |
| Unassign a CVE | ✗ | ✗ | ✗ | ✓ |
| Lift a CVE-request ban | — | — | — | ✓ ³ |
| Mark an orphan CVE rejected | — | — | — | ✓ |
| Resolve an orphan CVE reassignment task | — | — | — | ✓ |
| Move a native triage/draft report to GHSA ¹³ | ✗ | ✗ | ✓ | ✓ |
| Sync GHSA metadata for one advisory | ✗ | ✗ | ✓ | ✓ |
| Sync GHSA across one project | — | — | ✓ | ✓ |
| Sync GHSA across the org | — | — | ✗ | ✓ |
| Refresh all PMI repo mirrors / reconcile / discovery / webhook catch-up on demand | — | — | ✗ | ✓ |
| Configure the GitHub App | — | — | ✗ | ✓ |
| Retry a failed CVE push (single or bulk) | — | — | ✗ | ✓ |
| Browse the triage queue (Admin Console Inbox) | — | — | ✗ | ✓ |
| View operational SLA stats (Admin Console Stats) | — | — | ✗ | ✓ |
| View the GHSA operations dashboard (Admin Console GHSA) | — | — | ✗ | ✓ |
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
([INV-CVE-1](./invariant.md#inv-cve-1)). Available while the lifecycle state is `draft` or
`published`; blocked in `triage` (promote first) and `dismissed`
(reopen first — dismissal auto-cancels open requests, §6). The ban is set and
**lifted only by admins** (`workflows.services.unban_cve_requests`, surfaced on
`/admin/cves`); see [INV-CVE-3](./invariant.md#inv-cve-3).

⁴ Admins are the reviewers and cannot submit or withdraw submissions —
this avoids self-review ([INV-REVIEW-3](./invariant.md#inv-review-3)).

⁵ Project security-team members may publish only when *either* the
project is marked `is_mature_publisher` *or* the advisory carries
`review_status=approved` (see §7).

⁶ Reopen is the only allowed `state=dismissed` action besides viewing.
The reopened advisory returns to `Advisory.dismissed_from_state`
(`triage` or `draft`); the normal review and publication gates re-engage
from there. There is no direct `dismissed → published` transition
([INV-LIFECYCLE-4](./invariant.md#inv-lifecycle-4)). Defined by `can_reopen`.

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

⁹ Draft-only and **non-locking**: a pending request never removes the team's
edit/publish capability ([INV-AUTH-9](./invariant.md#inv-auth-9)), unlike the triage
routing flag (§6). **Native** drafts only — a GHSA-linked draft's project follows its
source repository in PMI (cf. footnote ¹, [INV-GHSA-1](./invariant.md#inv-ghsa-1)), so
`can_request_reassignment` is always false for it. Global admins cannot *request* (they reassign directly) but may
*withdraw*; only one request is pending at a time. An optional suggested target project
enables a one-click *accept* gated on the **suggested** project's security team (or a
global admin) — never the requester; accepting moves the advisory and appends a version.
A **global admin** additionally gets an in-banner project picker (`can_pick_reassignment_target`)
to resolve the request by reassigning to **any** project, not just the suggestion — sparing
them the full edit form; the destination authority is re-checked per chosen project by
`can_resolve_reassignment`. Defined by `can_request_reassignment` /
`can_withdraw_reassignment_request` / `can_accept_reassignment_suggestion` /
`can_pick_reassignment_target` / `can_resolve_reassignment`. See advisory-lifecycle §11.

¹⁰ **GHSA-linked advisories are never reviewed in AdvisoryHub** — their content is synced
from GitHub and isn't human-editable ([INV-GHSA-1](./invariant.md#inv-ghsa-1),
[INV-REVIEW-4](./invariant.md#inv-review-4)), so the three review actions (submit / withdraw /
revoke) are unavailable for them and a sync never invalidates an approval. Publication is
**system-driven** ([INV-GHSA-3](./invariant.md#inv-ghsa-3)): the EF feed mirrors the GHSA
automatically (auto-publish when GitHub publishes, auto-re-publish when synced content changes),
so `can_publish` returns `False` for **owners** — they get **no** Publish/Re-publish button. A
manual owner publish would be a no-op anyway, since `ghsa.services.refresh_for_publish` (GHSA must
be published on GitHub, not 404, no CVE conflict) only lets one through once GitHub has published.
Global admins keep a manual **break-glass** publish/retry (to re-drive a stuck/failed run, or
publish while `GHSA_AUTO_PUBLISH_ENABLED` is off), still gated by `refresh_for_publish` so they
cannot push it public ahead of GitHub. Defined by `can_submit_for_review` / `can_withdraw_review` /
`can_revoke_approval` / `can_publish`.

¹¹ **Withdrawing a published advisory** ([INV-WITHDRAW](./invariant.md#inv-withdraw)) mirrors the
publish authority: a global admin, or a **mature-publisher** project owner, may withdraw directly —
even with an assigned CVE (the orphan cascade then runs). A non-mature owner cannot withdraw
directly; they **request a withdrawal** an admin fulfils (§ withdrawal request). Withdrawal
re-exports the OSV/CSAF marked withdrawn (the documents stay in the feed) and flips the advisory to
`dismissed`. Defined by `can_withdraw_published`.

¹² **Comment lock (dispute cool-down).** An owner or admin can pause new comments on an advisory in
**any** lifecycle state (`Lock / unlock comments`, defined by `can_lock_comments` — owner-only:
global admins + the project security team). While a lock is in effect, only owners/admins may post —
collaborators and viewers are blocked from posting **any** comment (internal or not). The lock is enforced
through the single `can_comment` gate (consulted by the web view, JSON API, the `add_comment` service,
and the comment-form template), so it lands on every write path ([INV-AUTH-1](./invariant.md#inv-auth-1)).
It is **not** versioned — `comments_locked` is workflow metadata, absent from `Advisory.to_payload`.
Lock and unlock are recorded in the audit log and surfaced in the activity timeline
(`ADVISORY_COMMENTS_LOCKED` / `ADVISORY_COMMENTS_UNLOCKED`); an optional, secret-redacted reason is
posted as a **public** author-attributed comment (`record_action_note`, shown to everyone with
access — note this uses `add_comment(system=True)` to bypass the very lock it is setting). Defined
by `can_lock_comments` / `advisories.services.lock_advisory_comments` / `unlock_advisory_comments`.

¹³ **Move to GHSA** ([INV-GHSA-4](./invariant.md#inv-ghsa-4)). For a vulnerability filed as a
**native** report (`triage` or `draft`) that should have been a private vulnerability report on
GitHub. Owner-only (project security team + global admins), gated on `GHSA_FEATURE_ENABLED`, and
offered only when the advisory's project has at least one active GitHub repo with **private
vulnerability reporting (PVR)** enabled (cached flag, refreshed live when the picker opens). The
owner selects a target repo of the advisory's own project; AdvisoryHub authors a repository security
advisory there from the report content and converts the row **in place** to GHSA-linked — the one
sanctioned outbound *create* and `kind` flip. Requires step-up re-authentication. An assigned CVE
does **not** block the move (it is carried onto the new GHSA). The target repo must be an active repo
of the **same** project so the project never changes ([INV-GHSA-1](./invariant.md#inv-ghsa-1)) and
must have PVR enabled (re-validated live at move time). After the move the advisory follows the
inbound-only GHSA lifecycle ([INV-GHSA-3](./invariant.md#inv-ghsa-3)). Defined by `can_move_to_ghsa`
/ `ghsa.services.move_advisory_to_ghsa`.

---

## 6. State-conditioned overrides

The matrix in §5 assumes `state=draft` with `review_status` in
`{none, changes_requested}`. The other states and the review-pending
state add the following restrictions on top of (never in addition to)
the matrix:

- **`triage`.** Only the `owner` row of the matrix applies; collaborator
  and viewer rows are suppressed for *every* action other than `View
  advisory` and `Post comment`. The reporter's auto-granted
  viewer can therefore read and comment on their report, but cannot
  edit, publish, or request a CVE on it ([INV-AUTH-5](./invariant.md#inv-auth-5)). Internal
  comments still require collaborator+. In addition: `Submit advisory
  for review`, `Publish`, and `Request a CVE` are blocked for everyone
  (advisories must be promoted to `draft` first). The triage-specific actions
  `promote_triage_to_draft`, `dismiss_triage`, and
  `flag_for_admin_routing` follow the `owner` column, with the
  asymmetry that admins cannot flag (their queue is the destination).

  **GHSA-linked exception.** A GHSA-linked advisory can also sit in `triage`,
  but as a *read-only mirror* of GitHub's triage state
  ([INV-GHSA-3](./invariant.md#inv-ghsa-3)), not an untrusted human report.
  `can_triage` and `can_flag_for_admin_routing` return `False` for it, so
  promote / dismiss-via-triage / flag are all unavailable; it advances only by
  mirroring GitHub (triage → draft on acceptance, → published via auto-publish,
  → dismissed on close). It is also kept out of the admin-console Inbox work
  queue.

- **`triage` with `needs_admin_routing=True`.** Edit and triage
  decisions are further restricted to **global admins only**. Clearing
  the flag is owner-level: a global admin *or* the project's security
  team may unflag, retracting their own handoff — **except** on the
  `unsorted` sentinel project, where the flag cannot be cleared in place
  and is lifted only by reassigning to a real project (or promoting /
  dismissing). Admins resolve routing by reassigning the advisory to a
  real project — offered as an admin-only "assign to project" picker on
  the routing banner (`reassign_triage`), or via the edit form. Project
  owners may *flag* a misrouted report only when not already flagged and
  not on the `unsorted` sentinel project
  ([INV-AUTH-6](./invariant.md#inv-auth-6), [INV-INTAKE-4](./invariant.md#inv-intake-4)).

- **`review_status=submitted`.** `Edit advisory content` is blocked for
  every role except global admin. `Publish` is blocked for **everyone,
  including admins** — the pending review must be decided or withdrawn
  first ([INV-PERM-3](./invariant.md#inv-perm-3)). `Withdraw a pending review` is the
  submitter-side affordance for non-admin owners; admins decide via
  Approve / Request changes.

- **`published`.** `Dismiss advisory` is blocked (a published row stays
  published; corrections go through Edit + Re-publish). Edits append a
  new `AdvisoryVersion` and set `republish_required=True`, which makes
  the existing matrix-allowed `Publish` action surface a re-publish
  button ([INV-VERSION-1](./invariant.md#inv-version-1), [INV-REVIEW-4](./invariant.md#inv-review-4)).
  *(GHSA-linked exception, footnote ¹⁰: there is no owner re-publish button — a
  synced content change auto-re-publishes via [INV-GHSA-3](./invariant.md#inv-ghsa-3);
  only the admin break-glass surfaces the button.)* Non-admin edits that would
  otherwise invalidate an `approved` review reset `review_status`
  automatically; an admin's edit leaves the approval standing (the admin
  *is* the reviewer — explicit retraction goes through `Revoke an
  existing approval`).

- **`dismissed`.** While dismissed, `Publish`, `Submit advisory for
  review`, `Request a CVE`, and `Edit advisory content` are blocked for
  every role. `Reopen dismissed advisory` is the only state-change
  action available; it is owner-gated and returns the advisory to
  `Advisory.dismissed_from_state` ([INV-LIFECYCLE-4](./invariant.md#inv-lifecycle-4)). The advisory
  remains viewable per its grants throughout.

These are the only state overrides. Anything not mentioned here follows
the matrix unchanged.

---

## 7. Mature publisher

A project may be flagged `is_mature_publisher` on its `Project` row
([INV-PERM-2](./invariant.md#inv-perm-2)). When set, the `Publish` matrix entry for the project's
security-team members no longer requires `review_status=approved`: the
team may publish drafts directly, subject only to the universal
"no publish while review is submitted" gate from §6
([INV-PERM-1](./invariant.md#inv-perm-1), [INV-PERM-3](./invariant.md#inv-perm-3)).

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

Two rationales drive the gated set: **actions that emit to / reconfigure
an external system** (the public Git repo, the GitHub App, GHSA), and a
small number of **break-glass admin actions** that are irreversible or
have an org-wide blast radius. The actions currently gated by step-up
are:

- **Publish / retry a publication** — `publication/views.py`; the JSON
  API equivalents answer `401 step_up_required` instead of redirecting
  (`api/views_publication.py`).
- **Withdraw / approve a withdrawal of a published advisory** —
  `advisories/views.py` (`advisory_withdraw`, `advisory_approve_withdrawal`).
  Withdrawal re-exports OSV/CSAF and pushes to the same public Git repo as
  publish, so it carries the same gate. Merely *requesting* or *cancelling*
  a withdrawal request is *not* gated (no external push).
- **Connect the GitHub App / rescan installations** — `ghsa/views.py`.
- **Org-wide GHSA operations** — `ghsa/views.py`: `sync_all_ghsas`,
  `sync_all_pmi_repos`, `reconcile_now`, `discover_now`, `catch_up_webhooks`
  (the on-demand backstop triggers surfaced on the Admin Console GHSA
  dashboard). The project-scoped sync is *not* step-up gated.
- **Retry a failed CVE push to GHSA** — `ghsa/views.py` (`retry_cve_push`
  single, `retry_all_cve_pushes` bulk).
- **Break-glass admin actions** — `admin_console/views/`: forget a user
  (`users.py` `user_forget`, irreversible GDPR erasure), ban / unban a user
  (`user_ban` / `user_unban`, account lockout), and toggling maintenance mode
  (`maintenance.py`, org-wide write freeze — only the POST that flips the
  switch is gated; viewing the page is not).

The whole mechanism is switched off when `STEP_UP_REQUIRED=False`
(default in the `test` settings module so test clients can `force_login`
without an OIDC round-trip).

---

## 9. Enforcement surfaces

Every surface re-checks the same predicates from
`advisories/permissions.py`. Templates only display — they never decide
([INV-AUTH-1](./invariant.md#inv-auth-1)).

| Surface | Module(s) | Enforcement |
|---|---|---|
| Web views | `advisories/views.py`, `advisories/views_workflow.py`, `access/views.py`, `comments/views.py`, `publication/views.py`, `ghsa/views.py` | `require_advisory_permission` decorator or `AdvisoryPermissionMixin`; explicit `can_*` calls before each state-changing action. |
| JSON API | `api/views_*.py` | Same `can_*` predicates as the web views (e.g. `can_grant_access`, `can_view`, `can_see_internal_comment`, `can_publish`); list endpoints filter querysets through `can_view`. |
| Admin console | `admin_console/views/*` | All sections wrapped with `@admin_required`, which is `can_review` (global admin only). |
| Duplicate-check panel | `similarity/views.py` | Owner-only (`resolved_permission == "owner"`) on both the HTMX fragment and the re-run POST; the whole surface returns 404 while `SIMILARITY_CHECK_ENABLED` is off ([INV-SIM-1](./invariant.md#inv-sim-1), [INV-SIM-2](./invariant.md#inv-sim-2)). |
| Celery tasks | `publication/tasks.py`, `notifications/tasks.py`, `ghsa/tasks.py`, `similarity/tasks.py`, `projects/tasks.py`, `audit/tasks.py` | Act on behalf of the stored enqueuing user — predicates checked at enqueue (§3); execution re-validates task state; notification recipient lists are filtered again at send so revoked grants drop ([INV-PRIVACY-2](./invariant.md#inv-privacy-2)). |
| Public intake | `intake/views.py` | No authorization (`can_submit_triage_report` always returns true). Abuse control is the form-layer honeypot ([INV-INTAKE-1](./invariant.md#inv-intake-1)) plus rate limits keyed on anonymous/authenticated (`RATELIMIT_INTAKE_ANON` / `RATELIMIT_INTAKE_USER`). |
| Comment read filtering | `comments/services.py`, `comments/views.py` | `is_internal` is fixed at creation ([INV-COMMENT-1](./invariant.md#inv-comment-1)); visibility is re-checked at *read* and notification *send* time ([INV-COMMENT-2](./invariant.md#inv-comment-2)). |

---

## 10. Audit footprint

Every governance action that this document names emits exactly one
`AuditLogEntry` row at the moment it succeeds ([INV-AUDIT-3](./invariant.md#inv-audit-3)). The
authoritative catalogue of recordable actions is the `Action` enum in
`audit/models.py`; web-originated entries additionally capture the
requesting IP and User-Agent ([INV-AUDIT-4](./invariant.md#inv-audit-4)). The log is append-only
in both the application and database layers ([INV-AUDIT-1](./invariant.md#inv-audit-1)).

For an action to count as "audited" it must reach `audit.services.record`
or `record_from_request` — both funnel every user/CI-supplied string
through `redact_secrets` so tokens, key paths, and bearer URLs never
land in audit metadata ([INV-AUDIT-2](./invariant.md#inv-audit-2), [INV-SECRET-1](./invariant.md#inv-secret-1)).

---

## 11. Out of scope

- **Public anonymous reads.** The website at which published advisories
  are consumed lives in a separate Git repository; its access policy is
  not part of this document. Inside AdvisoryHub, "published" never
  grants implicit read ([INV-AUTH-7](./invariant.md#inv-auth-7)).
- **MITRE CVE assignment.** `workflows.CveRequestTask` is an internal
  queue; AdvisoryHub does not call any external CVE API and does not
  authorize external CNA actions.
- **IdP-side group management.** Group membership is managed in the
  IdP (Kanidm in dev). AdvisoryHub mirrors and reads it, but does not
  let anyone edit it from the application.
