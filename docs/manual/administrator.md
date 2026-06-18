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
identity provider; membership is mirrored on every login ([INV-OIDC-3](../specification/invariant.md#inv-oidc-3)). As with
all roles, you cannot grant admin from inside AdvisoryHub — it is managed in the
identity provider.

What only administrators can do (everything else is shared with owners):

- Review advisories — approve, request changes, revoke an approval.
- Reserve/reject CVEs and reconcile unassigned ("orphan") CVEs.
- Oversee publication failures across every project (owners can re-publish
  their own from the advisory page; only you see them all in one place).
- Re-home misrouted triage reports.
- Manage projects (including the mature-publisher flag) and sync rosters.
- Manage the GitHub App integration — org-wide GHSA syncs, CVE-push retries.
- Redact anyone's comment (authors can redact only their own).
- Ban/unban users and run GDPR "forget user".
- Turn maintenance mode on and off.
- Read the audit and access logs.

---

## 2. The Admin Console

The Admin Console lives at **`/admin/`** and is the only admin surface — Django's
built-in admin site is not enabled (see §12). Its landing page is the **Inbox**: a
single, unified work queue that gathers everything waiting on an administrator:

- triage reports needing a decision (and the subset flagged as misrouted),
- advisories submitted for review,
- queued CVE requests,
- failed publication tasks,
- orphan CVEs awaiting reconciliation, and their reassignment tasks.

Use the category filter to focus on one kind of work. The Console's left nav also
links directly to the **Projects**, **Users**, **Groups**, **CVE Assignment**,
**Publication**, **Audit logs**, **Access log**, and **Maintenance** sections
described below.

---

## 3. Reviewing advisories

When an owner submits a draft for review, it appears in your Inbox. Open the
advisory; the **Review** card in the sidebar gives you the decision buttons:

- **Approve** — the advisory becomes approved and its team can publish it.
- **Request changes** — sends it back to the owner to revise and resubmit.

You can also **Revoke approval** from the **Review** card if something needs
another look before it goes out — this re-blocks publishing.

Two rules to remember:

- **Administrators are the only reviewers**, and **you cannot submit or withdraw
  a submission yourself** — that would be self-review ([INV-REVIEW-3](../specification/invariant.md#inv-review-3)). Owners
  submit; you decide.
- **No one can publish while a review is still submitted** — it must be decided
  or withdrawn first.

See the owner's side of this in the
[Security-Team Guide §7](./security-team.md#7-review).

---

## 4. Managing CVEs

The **CVE Assignment** page (`/admin/cves/`) is the internal CVE queue. (AdvisoryHub does
**not** call MITRE; this is an internal workflow — the actual reservation at
cve.org is something you do out-of-band and then record here.)

**Acting on a CVE request.** On the **CVE Assignment** page, each queued request
is a row with an inline action:

- **Reserve** — type the CVE identifier (`CVE-YYYY-NNNN`) into the row and click
  **Assign**; it is attached to the advisory. If the advisory is already published,
  this marks it as needing re-publication so the CVE shows up publicly.
- **Reject** — click **Reject…** to give a reason; optionally **ban future CVE
  requests** for that advisory if it should never get one.

**Unassigning and orphan CVEs.** Only an administrator can **unassign** a CVE from
an advisory — the trash icon beside the assigned CVE on the advisory page opens a
"Remove CVE assignment" dialog — for example before dismissing an advisory that
holds one. Unassigning produces an **orphan CVE**: a CVE that was reserved but no
longer belongs to a live advisory and must be reconciled at cve.org.

- **Mark an orphan rejected** — the orphan's row on the **CVE Assignment** page has
  a **Mark rejected at cve.org** button to record that you've done so.
- **Resolve a reassignment task** — the reassignment task's row on the **CVE
  Assignment** page has a **Resolve** button. The task is created when a dismissed
  advisory whose orphan CVE you had already **marked rejected** is **reopened**:
  you decide whether to **reassign** that CVE back to it or **replace** it with a
  new one. (A CVE that was still merely orphaned at reopen time is re-attached
  automatically — no task appears.)

On a **GHSA-linked** advisory, reserving a CVE also pushes the id to the GHSA on
GitHub. The advisory's GHSA panel shows the push status; failed pushes can be
retried with the **Retry** button in the **Failed CVE pushes** table on the
**GHSA** page, and if upstream already carries a *different* CVE id, publication is
blocked until you reconcile (§11).

The full CVE-request and orphan state machines are in
[`advisory-lifecycle.md`](../specification/advisory-lifecycle.md).

---

## 5. Publication oversight

The **Publication** page (`/admin/publications/`) lists publication attempts —
in particular the **failed** ones. For each failed row you can:

- read the (secret-redacted) error message — tokens and credentials never appear
  here ([INV-SECRET-1](../specification/invariant.md#inv-secret-1));
- **Retry** the publication (the button on the row), which is the right move for a
  transient failure such as a network blip or a momentary push rejection (owners
  can equally re-publish from the advisory page — this page is where *every*
  project's failures gather);
- preview or download the generated **OSV**, **CSAF**, and — when a CVE is
  assigned — **CVE** artifacts via the links on the row.

Remember an advisory flips to *published* only after a successful Git push
([INV-LIFECYCLE-3](../specification/invariant.md#inv-lifecycle-3)); a failed task leaves the state untouched, so retrying is
safe.

---

## 6. Re-homing misrouted triage reports

Reports submitted with **"I don't know"** as the project, or flagged by an owner
as misrouted, land in your Inbox for routing. Open such a report and **promote**
it — because it isn't yet on a real project, promotion requires you to **choose
the destination project**. Only administrators can route these reports — while
flagged, they are locked to you ([INV-INTAKE-4](../specification/invariant.md#inv-intake-4)). The flag itself is not a
one-way door, though: the owner who raised it can retract it to take the report
back, and you can clear it without promoting if it was raised in error.

---

## 7. Projects

The **Projects** page (`/admin/projects/`) lists every project. You can:

- **Create** a project (`/admin/projects/new/`) and **edit** one — click a project
  in the list to open its edit page (name, security team, and settings).
- **Toggle the mature-publisher flag.** When set, that project's security team can
  publish drafts **without** a per-advisory approval ([INV-PERM-2](../specification/invariant.md#inv-perm-2)). This flag
  lives on the project (not in the identity provider), precisely so you can change
  it here and have the change audited.
- **Sync the security-team roster** — the project's edit page has a **Sync
  security team** button (under "Security-team roster") that pre-provisions
  notification-only ("shadow") accounts for Eclipse roster members who haven't
  signed in yet, so `@team` mentions and alerts reach them. It confers no in-app
  access ([INV-OIDC-5](../specification/invariant.md#inv-oidc-5)), and the button appears only on deployments that
  enable roster sync.

---

## 8. Users and groups

The **Users** page (`/admin/users/`) lets you search and filter the directory
(including by **ban status**). Click a user to open their detail page — their
groups, their advisory grants and invitations, and their notification settings.
From there you can:

- **Ban / unban** — the **Ban this account…** button (or **Unban account** for a
  banned user) under "Account access". Banning is the one app-side override of
  identity-provider authority: it denies login and drops the user's live session
  immediately, rather than waiting for an identity-provider change to propagate
  ([INV-AUTH-8](../specification/invariant.md#inv-auth-8)). It is reversible and audited at both ends.
- **Forget user (GDPR)** — the **Forget this account…** button under "Right to be
  forgotten (GDPR)" erases a user's personal data across the system. This is
  irreversible; use it only for genuine data-subject erasure requests.

The **Groups** page (`/admin/groups/`) is **read-only**: groups and their
membership are owned by the identity provider, which AdvisoryHub only mirrors
([INV-OIDC-2](../specification/invariant.md#inv-oidc-2)). Click a group to open its read-only detail page. To change
who is in a group, change it in the identity provider.

---

## 9. Maintenance mode

The **Maintenance** page (`/admin/maintenance/`) toggles maintenance mode. While
it is **on**, only global administrators may make changes — every other user's
writes are paused server-side, while reads continue ([INV-MAINT-1](../specification/invariant.md#inv-maint-1)). Use it for
deployments or data work where you need a stable, write-quiet system. Turn it off
to restore normal operation.

---

## 10. Audit and access logs

- **Audit log** (`/admin/audit/`) — the append-only record of every governance
  action (create, edit, grant, review, publish, ban, …). It cannot be altered or
  deleted, in either the application or the database ([INV-AUDIT-1](../specification/invariant.md#inv-audit-1)). Use it to
  answer "who did what, when".
- **Access log** (`/admin/access-log/`) — who viewed or accessed which advisory.

---

## 11. GitHub (GHSA) integration

On deployments that enable the GHSA integration, projects using GitHub's
private vulnerability reporting get **GHSA-linked** advisories whose content
syncs from GitHub (the team-facing side is in the
[Security-Team Guide §10](./security-team.md#10-ghsa-linked-advisories)). The
integration-admin controls are yours alone:

- **Connect the GitHub App** at `/ghsa/connect/` — reached from the **GHSA** page's
  **Configure GitHub App →** link (or by going to `/ghsa/connect/` directly). The
  page shows the installation state, lets you **rescan installations**, and
  displays the webhook URL to configure on GitHub.
- **Org-wide GHSA sync** — the **Sync all GHSAs** button under **Operations** on
  the **GHSA** page refreshes every GHSA-linked advisory across all projects in one
  go. (Per-advisory refresh is available to the teams themselves on the advisory
  page.)
- **Retry a failed CVE push** — the **Retry** button in the **Failed CVE pushes**
  table on the **GHSA** page. When a CVE is reserved on a GHSA-linked advisory,
  AdvisoryHub pushes the id to GitHub; a failed push surfaces here for retry, and a
  conflicting upstream CVE id blocks publication until you reconcile it (§4).

Connecting, rescanning, org-wide syncs, and CVE-push retries all require
step-up authentication (§13).

---

## 12. No Django admin

AdvisoryHub does **not** enable Django's built-in admin site — there is no
`/django-admin/`. It was removed deliberately: its low-level, direct model editing
bypassed the guard rails and the audit log that the rest of the app enforces, so it
was a way to change data without leaving an audit trail. The Admin Console (§2) is
the only administrative surface; for genuine break-glass database access, an
operator with shell access uses `manage.py shell` / `dbshell`.

---

## 13. Step-up authentication

Some sensitive actions require a **recent re-login** even though you're
already signed in ([permissions.md §8](../specification/permissions.md)):

- **Publishing** an advisory (including re-publishing and retrying a failed
  publication).
- **Connecting the GitHub App** or rescanning its installations.
- **Org-wide GHSA syncs** and **CVE-push retries** (project- and
  advisory-scoped syncs are not gated).

If prompted, complete the quick re-authentication and the action proceeds.

---

## Related guides

- [Manual index](./README.md) — concepts, lifecycle, glossary.
- [Security-Team Guide](./security-team.md) — the authoring/triage/publish
  lifecycle that you, as an owner everywhere, can also perform.
- [Collaborator & Viewer Guide](./collaborator-and-viewer.md) — the per-advisory
  roles you grant to non-team members.
