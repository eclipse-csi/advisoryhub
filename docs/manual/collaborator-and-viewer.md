# Collaborator & Viewer Guide

**Audience:** people who have been given access to **specific** advisories but
are **not** on the owning project's security team — for example an external
maintainer, a reporter following their own report, or a colleague pulled in to
help on one advisory.

If you *are* on a project's security team, read the
[Security-Team Guide](./security-team.md) instead; you have owner access to all
of that project's advisories and don't need per-advisory grants.

For shared concepts (signing in, the lifecycle, the glossary), see the
[manual index](./README.md).

---

## 1. The two roles

You hold one of two roles **per advisory** — you might be a collaborator on one
and a viewer on another:

| You can… | Viewer | Collaborator |
|---|---|---|
| View the advisory and its version history | ✓ | ✓ |
| Post **public** comments | ✓ | ✓ |
| See and post **internal** comments | ✗ | ✓ |
| Edit the advisory's content | ✗ | ✓ |
| Grant access, dismiss, request a CVE, submit for review, or publish | ✗ | ✗ |
| See other users' email addresses | ✗ | ✗ |

The last two rows are owner/administrator territory — even as a collaborator you
cannot manage access or move the advisory through its lifecycle, and you see
other people by **display name** only (where someone has no display name, their
email is shown masked, like `a•••@example.org` — [INV-PRIVACY-4](../specification/invariant.md#inv-privacy-4)). You always
see your *own* email.

The authoritative, state-by-state capability matrix is in
[`permissions.md`](../specification/permissions.md).

---

## 2. How you got access

There are three ways access reaches you; all of them are set up by an owner or
administrator:

- **Direct grant** — you were granted viewer or collaborator on the advisory.
- **Group grant** — a group you belong to was granted access; you inherit it.
- **Email invitation** — you were invited by email before you had an account.
  The invitation becomes a real grant automatically the **first time you sign
  in** with that email address (matching is case-insensitive — [INV-ACCESS-2](../specification/invariant.md#inv-access-2)).
  Invitations **expire after 14 days** ([INV-ACCESS-3](../specification/invariant.md#inv-access-3)); if yours lapsed, ask the
  owner to re-send it.

> **"I signed in but I see nothing."** An empty advisory list means you don't yet
> hold any grants — your access hasn't been set up, or an email invitation went to
> a different address than the one you logged in with. Contact whoever invited you.

Finding your advisories: after signing in you land on `/advisories/`. Use the
search box and the **state tabs** (All / triage / draft / published / dismissed)
to narrow the list; click any row to open the advisory.

---

## 3. Viewing an advisory

The advisory detail page shows its current content, its state, and the activity
timeline. As a viewer or collaborator you can:

- **Read the full advisory** — summary, details, affected packages, references,
  severity, credits, and any assigned CVE.
- **Browse the version history** — open the history view (`…/history/`) to see
  every past version, and open a diff to compare two versions
  (`…/versions/<n>/diff/`). Nothing is ever silently overwritten.
- **Follow the Activity timeline** — the advisory page ends with a merged,
  chronological view of comments and recorded actions.

---

## 4. Commenting

Scroll to the **Activity** timeline at the end of the advisory page and use the
comment box.

- **Public vs internal.** Public comments are visible to everyone who can see the
  advisory. **Internal** comments are visible only to collaborators, owners, and
  administrators — viewers never see them. If you are a **viewer**, every comment
  you post is public. If you are a **collaborator**, you can choose internal when
  posting. Whether a comment is internal is fixed at posting time and cannot be
  changed afterward.
- **Mentions.** Type `@` and a name to notify a specific person, or `@team` to
  notify a project's security team. Mentioned people are emailed.
- **Editing your comments.** You can edit a comment you wrote; edits are
  versioned and you can view a comment's history. Newly added mentions in an
  edit notify the newly mentioned people.
- **Redacting comments.** You can redact a comment you wrote (administrators
  can redact any comment). Redaction hides the text for everyone but keeps the
  entry visible in the timeline; a redacted comment can no longer be edited.

---

## 5. Editing (collaborators only)

If you are a **collaborator**, the advisory shows an **Edit** action
(`…/edit/`). A few things to understand before you edit:

- **Every content change appends a new version** — the previous version is kept
  intact and remains in the history ([INV-VERSION-1](../specification/invariant.md#inv-version-1)). You cannot lose earlier
  content.
- **Editing a *published* advisory does not change what's public on its own.** It
  marks the advisory as needing re-publication; an owner or administrator then
  re-publishes to push your changes out.
- **Editing can reset an approval.** If the advisory had been approved in review,
  your edit (as a non-administrator) invalidates that approval, and an owner will
  need to resubmit it for review.

When editing is **not** available to you, even as a collaborator:

- while the advisory is still in **triage** (only owners act on triage reports —
  you can still view and comment);
- while it is **submitted for review** (locked until an administrator decides);
- while it is **dismissed**.

In those situations the Edit action is hidden or refused — that's by design, not
a fault.

---

## 6. Notifications

AdvisoryHub keeps you informed about advisories you're involved with:

- **In-app inbox:** `/notifications/inbox/` (mark items read, or mark all read).
- **Email:** sent for relevant events on your advisories. Emails deliberately
  carry no advisory content — just the event, the advisory id, the project,
  and a footer explaining why you received it and where to change settings.
- **Preferences:** set your defaults at `/notifications/preferences/`. Each
  advisory page also has a **Notifications** panel to override them with a
  preset — follow your defaults, everything, important only, unsubscribe, or
  custom per-event choices. "Only when mentioned" is the lowest level: mentions
  always notify, and there is no "never".

---

## Related guides

- [Manual index](./README.md) — concepts, lifecycle, glossary.
- [Reporter's Guide](./reporter.md) — filing a vulnerability report.
- [Security-Team Guide](./security-team.md) — the owner role, if you join a
  project's security team.
