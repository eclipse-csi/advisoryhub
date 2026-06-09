# Administrator & Reviewer Guide

**Audience:** global administrators — members of the AdvisoryHub admin group in
the identity provider. You are an **owner on every advisory**, the **only people
who review advisories**, and the operators of the **Admin Console**. You also
hold the CVE/CNA-side and integration controls.

Because you are an owner everywhere, the whole
[Security-Team Guide](./security-team.md) applies to you too (creating, editing,
publishing). **This guide covers the powers that are yours alone.** For shared
concepts, see the [manual index](./README.md).

---

## 1. Who this guide is for

You become an administrator by being in the admin group in the Eclipse Foundation
identity provider; membership is mirrored on every login ([INV-OIDC-3]). That
same membership also grants you Django's low-level admin site (§11). As with all
roles, you cannot grant admin from inside AdvisoryHub — it is managed in the
identity provider.

What only administrators can do (everything else is shared with owners):

- Review advisories — approve, request changes, revoke an approval.
- Reserve/reject CVEs and reconcile unassigned ("orphan") CVEs.
- Retry failed publications.
- Re-home misrouted triage reports.
- Manage projects (including the mature-publisher flag) and sync rosters.
- Ban/unban users and run GDPR "forget user".
- Turn maintenance mode on and off.
- Read the audit and access logs.

---

## 2. The Admin Console

The Admin Console lives at **`/admin/`** (this is *not* the Django admin site at
`/django-admin/` — see §11). Its landing page is the **Inbox**: a single,
unified work queue that gathers everything waiting on an administrator:

- triage reports needing a decision (and the subset flagged as misrouted),
- advisories submitted for review,
- queued CVE requests,
- failed publication tasks,
- orphan CVEs awaiting reconciliation, and their reassignment tasks.

Use the category filter to focus on one kind of work. The Console's left nav also
links directly to the **CVEs**, **Publications**, **Audit**, **Access log**,
**Projects**, **Users**, **Groups**, and **Maintenance** sections described
below.

---

## 3. Reviewing advisories

When an owner submits a draft for review, it appears in your Inbox. Open the
advisory and decide (`…/review/decide/`):

- **Approve** — the advisory becomes approved and its team can publish it.
- **Request changes** — sends it back to the owner to revise and resubmit.

You can also **revoke an existing approval** (`…/revoke-approval/`) if something
needs another look before it goes out — this re-blocks publishing.

Two rules to remember:

- **Administrators are the only reviewers**, and **you cannot submit or withdraw
  a submission yourself** — that would be self-review ([INV-REVIEW-3]). Owners
  submit; you decide.
- **No one can publish while a review is still submitted** — it must be decided
  or withdrawn first.

See the owner's side of this in the
[Security-Team Guide §7](./security-team.md#7-review).

---

## 4. Managing CVEs

The **CVEs** page (`/admin/cves/`) is the internal CVE queue. (AdvisoryHub does
**not** call MITRE; this is an internal workflow — the actual reservation at
cve.org is something you do out-of-band and then record here.)

**Acting on a CVE request** (`/admin/cve/<id>/transition/`):

- **Reserve** — enter the CVE identifier (`CVE-YYYY-NNNN`); it is attached to the
  advisory. If the advisory is already published, this marks it as needing
  re-publication so the CVE shows up publicly.
- **Reject** — give a reason; optionally **ban future CVE requests** for that
  advisory if it should never get one.

**Unassigning and orphan CVEs.** Only an administrator can **unassign** a CVE
from an advisory (`…/unassign-cve/`) — for example before dismissing an advisory
that holds one. Unassigning produces an **orphan CVE**: a CVE that was reserved
but no longer belongs to a live advisory and must be reconciled at cve.org.

- **Mark an orphan rejected** (`/admin/orphans/<id>/mark-rejected/`) — record that
  you have marked it rejected at cve.org.
- **Resolve a reassignment task** (`/admin/orphans/reassignment/<id>/resolve/`) —
  when a dismissed advisory that owned an orphan CVE is **reopened**, you decide
  whether to **reassign** the same CVE back to it or **replace** it with a new
  one.

The full CVE-request and orphan state machines are in
[`advisory-lifecycle.md`](../specification/advisory-lifecycle.md).

---

## 5. Publication oversight

The **Publications** page (`/admin/publications/`) lists publication attempts —
in particular the **failed** ones. For each you can:

- read the (secret-redacted) error message — tokens and credentials never appear
  here ([INV-SECRET-1]);
- **retry** the publication (`/publication/tasks/<id>/retry/`), which is the right
  move for a transient failure such as a network blip or a momentary push
  rejection;
- preview or download the generated **OSV** and **CSAF** artifacts
  (`/publication/tasks/<id>/artifact/<kind>/`).

Remember an advisory flips to *published* only after a successful Git push
([INV-LIFECYCLE-3]); a failed task leaves the state untouched, so retrying is
safe.

---

## 6. Re-homing misrouted triage reports

Reports submitted with **"I don't know"** as the project, or flagged by an owner
as misrouted, land in your Inbox for routing. Open such a report and **promote**
it — because it isn't yet on a real project, promotion requires you to **choose
the destination project**. Only administrators can clear a routing flag and
decide where one of these reports belongs ([INV-INTAKE-4]).

---

## 7. Projects

The **Projects** page (`/admin/projects/`) lists every project. You can:

- **Create** a project (`/admin/projects/new/`) and **edit** one
  (`/admin/projects/<id>/edit/`) — name, security team, and settings.
- **Toggle the mature-publisher flag.** When set, that project's security team can
  publish drafts **without** a per-advisory approval ([INV-PERM-2]). This flag
  lives on the project (not in the identity provider), precisely so you can change
  it here and have the change audited.
- **Sync the security-team roster** (`/admin/projects/<id>/sync-roster/`) — refresh
  the project's team membership from the Eclipse roster.

---

## 8. Users and groups

The **Users** page (`/admin/users/`) lets you search and filter the directory
(including by **ban status**). Open a user (`/admin/users/<id>/`) to see their
groups, their advisory grants and invitations, and their notification settings.
From there you can:

- **Ban / unban** (`…/ban/`, `…/unban/`) — banning is the one app-side override of
  identity-provider authority: it denies login and drops the user's live session
  immediately, rather than waiting for an identity-provider change to propagate
  ([INV-AUTH-8]). It is reversible and audited at both ends.
- **Forget user (GDPR)** (`…/forget/`) — erase a user's personal data across the
  system. This is irreversible; use it only for genuine data-subject erasure
  requests.

The **Groups** page (`/admin/groups/`) is **read-only**: groups and their
membership are owned by the identity provider, which AdvisoryHub only mirrors
([INV-OIDC-2]). To change who is in a group, change it in the identity provider.

---

## 9. Maintenance mode

The **Maintenance** page (`/admin/maintenance/`) toggles maintenance mode. While
it is **on**, only global administrators may make changes — every other user's
writes are paused server-side, while reads continue ([INV-MAINT-1]). Use it for
deployments or data work where you need a stable, write-quiet system. Turn it off
to restore normal operation.

---

## 10. Audit and access logs

- **Audit log** (`/admin/audit/`) — the append-only record of every governance
  action (create, edit, grant, review, publish, ban, …). It cannot be altered or
  deleted, in either the application or the database ([INV-AUDIT-1]). Use it to
  answer "who did what, when".
- **Access log** (`/admin/access-log/`) — who viewed or accessed which advisory.

---

## 11. Django admin

Your admin membership also gives you Django's built-in admin at
**`/django-admin/`**. This is a low-level, direct view of the database models. It
bypasses the friendly workflows and guard rails of the rest of the app, so use it
sparingly — for inspection and genuine break-glass fixes, not routine work. The
Admin Console (§2) is the right tool for day-to-day administration.

---

## 12. Step-up authentication

A couple of sensitive actions require a **recent re-login** even though you're
already signed in ([permissions.md §8](../specification/permissions.md)):

- **Publishing** an advisory.
- **Connecting or modifying the GitHub App** integration.

If prompted, complete the quick re-authentication and the action proceeds.

---

## Related guides

- [Manual index](./README.md) — concepts, lifecycle, glossary.
- [Security-Team Guide](./security-team.md) — the authoring/triage/publish
  lifecycle that you, as an owner everywhere, can also perform.
- [Collaborator & Viewer Guide](./collaborator-and-viewer.md) — the per-advisory
  roles you grant to non-team members.
