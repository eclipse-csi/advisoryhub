# Weekly Technical-Debt Review — Data Model (2026-07-01)

**Scope:** data-model / schema debt (ORM models, migrations, serialization, API payloads).
**Mode:** PR — one small, safe, focused change shipped this week.
**Prioritization:** strict, scored `Impact × Confidence ÷ Effort` (see [rubric](#scoring)).

---

## 1. Executive summary

The schema is young and disciplined: append-only audit + advisory triggers, row-level
security, immutable versioned payloads, derived-but-indexed severity fields, and a clean
migration history (no `RemoveField`/`RenameField` churn). The most valuable data-model
debt this week was a **write-only field**: a failed GHSA sync recorded its error into
`Advisory.ghsa_metadata`, a JSONField that **no code path ever reads** — while two nearby
comments falsely claimed "the dashboard surfaces the sync error." The error was invisible.

Per maintainer decision, this was **wired up** (rather than deleted): a first-class,
surfaced `Advisory.ghsa_sync_error` field now mirrors the existing `Project.last_pmi_sync_error`
pattern — recorded (redacted) on every handled sync failure, cleared on the next success,
and shown as a banner on the GHSA panel. The stale comments are now true.

The remaining write-only writes to `ghsa_metadata` (raw payload, `missing_upstream` marker)
are deferred to the backlog as a deliberate keep-or-remove decision.

## 2. Commands / tools run

```
DJANGO_SETTINGS_MODULE=config.settings.test  uv run python manage.py makemigrations advisories --name advisory_ghsa_sync_error
DJANGO_SETTINGS_MODULE=config.settings.test  uv run python manage.py makemigrations --check --dry-run   # No changes detected
DJANGO_SETTINGS_MODULE=config.settings.test  uv run python manage.py check                              # 0 issues
DJANGO_SETTINGS_MODULE=config.settings.test  uv run pytest ghsa/ advisories/ --create-db                # all pass
DJANGO_SETTINGS_MODULE=config.settings.dev   uv run mypy ghsa advisories                                # Success, no issues
uv run ruff check advisories/ ghsa/                                                                     # All checks passed
uv run ruff format advisories/ ghsa/                                                                    # formatted
uv run python dev/check_template_comments.py templates/advisories/_ghsa_panel.html                      # OK
```
Plus three read-only exploration passes (model inventory, migration audit, read/write path
tracing) and targeted `grep`/`ripgrep` verification of every claim below.

## 3. Findings (top 10, ranked)

Severity: **P0** correctness/security/data-loss · **P1** major · **P2** moderate · **P3** cleanup.
Effort: **S** <½ day · **M** 1–2 days · **L** several days · **XL** project-sized.

| # | Finding | Sev | Conf | Effort | Score | Owner |
|---|---------|-----|------|--------|-------|-------|
| 1 | **[FIXED]** GHSA sync error written to never-read `ghsa_metadata`; comments claim it's surfaced but it isn't | P2 | 5 | S | 7.5 | Backend/GHSA |
| 2 | `ghsa_metadata` residual write-only writes (raw payload, `missing_upstream`) — stored, never read | P3 | 5 | S | 5.0 | Backend/GHSA |
| 3 | `comments_locked_at` / `comments_locked_by` — written, never read (actor+timestamp already in audit log) | P3 | 4 | S | 4.0 | Backend |
| 4 | `audit.action`: 16 sequential `AlterField` migrations (`0004`–`0019`) — squash candidate | P3 | 5 | M | 2.5 | Backend/DBA |
| 5 | Tri-state `BooleanField(null=True, default=None)` — `AdvisoryNotificationPreference.on_*`, `ProjectGitHubRepository.pvr_enabled` | P3 | 3 | M | 1.5 | Backend |
| 6 | `AdvisoryAccessGrant` `(principal_type, principal_id)` weak reference vs FK — no DB-level integrity | P2 | 3 | L | 1.1 | Backend/DBA |
| 7 | `severity_level` / `severity_score` denormalized from `severity` JSON — drift risk if a write path skips the save hook | P3 | 3 | S | 3.0 | Backend |
| 8 | `SimilarityCheck.candidate_pool_size` — read only into audit metadata | P3 | 4 | S | 2.0 | Backend |
| 9 | `AccessLogEntry` monthly range-partition maintenance — DEFAULT partition trap if the extension task stalls | P2 | 3 | M | 1.1 | Ops/DBA |
| 10 | Stale `seed_demo` docstring claiming `ghsa_metadata` is "rendered" | P3 | 4 | S | 2.0 | Backend |

### Detail & evidence

**1 — GHSA sync error dumped into never-read `ghsa_metadata` (FIXED THIS WEEK).**
`ghsa/services.py` wrote `advisory.ghsa_metadata = {"sync_error": redact_secrets(str(exc))}`
in `create_ghsa_linked_advisory` and `move_advisory_to_ghsa`, with comments claiming "the
dashboard surfaces the sync error." Grep proved **zero** reads of `.ghsa_metadata` anywhere
(absent from `Advisory.to_payload()`; not in any template, `admin_console/`, `api/`, or
`ghsa/` view). The GHSA panel (`templates/advisories/_ghsa_panel.html:27`) shows only
`ghsa_metadata_synced_at`. So a failed sync was invisible. The codebase already had the
correct pattern (`Project.last_pmi_sync_error`, `projects/models.py:61`, rendered at
`templates/admin_console/project_form.html:70`). **Confidence 5** (grep-proven).

**2 — `ghsa_metadata` residual write-only writes.** After fix #1, `ghsa_metadata` still
receives the full upstream payload (`ghsa/services.py`, normal-sync branch) and a
`{"missing_upstream": True}` marker — both still never read. It duplicates content already
stored structurally (`details`, `summary`, `severity`) and retains the full raw GHSA JSON
(potentially embargoed) indefinitely. **Deferred** (see §6): keep-for-debugging vs. remove
is a maintainer call, and it is spec-documented (`requirements.md`). **Confidence 5.**

**3 — `comments_locked_at` / `comments_locked_by`.** Written in `advisories/services.py`
(lock/unlock) but never read: templates show `comments_locked` (bool) and
`comments_lock_reason`; the lock actor+timestamp already live in the audit log
(`ADVISORY_COMMENTS_LOCKED`). **Confidence 4** (no read site found).

**4 — `audit.action` migration churn.** `audit/migrations/0004`–`0019` are 16 sequential
`AlterField` operations that only extend the `action` choices list. A squash would shorten
fresh-DB setup. Migration-graph change → not "safe small." **Confidence 5.**

**5 — Tri-state nullable booleans.** `BooleanField(null=True, default=None)` encodes
inherit/on/off as a nullable bool (`notifications` prefs, `ProjectGitHubRepository.pvr_enabled`).
Likely intentional; an explicit enum would be clearer but is a behavior-touching refactor.
**Confidence 3 — do not rewrite** without confirmation.

**6 — `AdvisoryAccessGrant` weak principal reference.** `(principal_type, principal_id)`
instead of nullable `user`/`group` FKs + a `CheckConstraint`. No DB-level referential
integrity (orphan risk if a user/group is deleted out-of-band). Deliberate polymorphic
design; a migration is L-effort and touches authorization. **Confidence 3 — do not rewrite.**

**7 — `severity_level`/`severity_score` denormalization.** Derived from the `severity` JSON
at save time and indexed for list filtering (a sound perf choice). Risk: a write path that
bypasses the save hook (e.g. `.update()`/`bulk_update`) drifts. Worth a management-command
consistency check, not a schema change. **Confidence 3.**

**8 — `SimilarityCheck.candidate_pool_size`.** Written once per check, read only into audit
metadata — never surfaced or serialized. Marginal; could move to audit metadata. **Confidence 4.**

**9 — `AccessLogEntry` partition maintenance.** Range-partitioned by month
(`audit/migrations/0003_accesslogentry.py`, via `SeparateDatabaseAndState`). If the runtime
partition-extension task stalls, inserts fall into the DEFAULT partition (slow, unindexed).
Operational, not schema. **Confidence 3.**

**10 — Stale `seed_demo` docstring.** `admin_console/management/commands/seed_demo.py:1105-1108`
says the canned `ghsa_metadata` payload lets devs "see the synced metadata rendered" — it is
not rendered. Mostly moot after fix #1's comment corrections; the seed still stores the blob.
**Confidence 4.**

## 4. Recommended order of work

1. **This week (done):** #1 — surface the GHSA sync error.
2. **Next:** #3 (drop two write-only comment-lock columns) and #8 — both small, low-risk.
3. **Then:** #2 — decide keep-or-remove `ghsa_metadata`; #7 — add a severity-consistency check.
4. **Scheduled/ops:** #4 (squash during a migration-quiet window); #9 (verify the partition task + alerting).
5. **Backlog, needs design + confirmation:** #5, #6.

## 5. What was fixed in this week's commit

**Problem.** A failed GHSA sync recorded its error into a field nothing reads; the code
comments claimed the dashboard surfaced it. Operators had no visibility into sync failures.

**Fix.** New `Advisory.ghsa_sync_error = TextField(blank=True)` (mirrors
`Project.last_pmi_sync_error`), deliberately excluded from `to_payload()` so it is never
versioned (INV-VERSION-1). A `record_ghsa_sync_error()` service helper persists the redacted
error (INV-SECRET-*) via `update_fields`, called from every caller that already catches
`GitHubApiError` (create, move, reconcile, manual refresh). `sync_single_ghsa` clears it to
`""` on any successful reach to GitHub (both the payload and `missing_upstream` branches).
The panel shows a "Last sync failed" banner. The two stale comments are corrected.

*Why the helper lives outside `sync_single_ghsa`:* that function is `@transaction.atomic`
and the fetch raises inside it, so an error write there would be rolled back. Recording it
in the (post-rollback) caller, scoped by `update_fields`, is the safe placement.

**Files changed.**
- `advisories/models.py` — new `ghsa_sync_error` field + comment.
- `advisories/migrations/0011_advisory_ghsa_sync_error.py` — `AddField`.
- `ghsa/services.py` — `record_ghsa_sync_error` helper; set-on-failure at 3 call sites
  (replacing the `ghsa_metadata` dumps); clear-on-success in both `sync_single_ghsa` branches;
  two comments corrected.
- `ghsa/views.py` — persist the error in `refresh_advisory_ghsa`'s except (survives redirect).
- `templates/advisories/_ghsa_panel.html` — "Last sync failed" banner (CSP-safe, no inline style).
- `ghsa/tests/test_services.py` — 3 tests (record-on-failure, clear-on-success, clear-on-deletion).
- `docs/specification/requirements.md` — document `ghsa_sync_error` in the same PR.

**Validation.** `pytest ghsa/ advisories/ --create-db` all pass (incl. the 3 new tests);
`makemigrations --check` clean; `manage.py check` clean; `mypy` clean; `ruff check`/`format`
clean; template-comment guard OK.

**Risks / rollback.** Low — additive field + additive display, no data loss, no removal of a
spec-documented field, redaction preserved. Intended behavior change: a failed sync now
persists and shows a banner where it was previously invisible (covered by the new test).
Rollback = revert the commit (`AddField` reverse drops the column).

## 6. Follow-up backlog (intentionally out of scope)

- **#2 `ghsa_metadata` keep-or-remove** — deferred: removal touches a spec-documented field
  and needs a keep-for-debugging decision. Now that errors have their own field, its only
  remaining writes are the raw payload + `missing_upstream` marker.
- **#3 comment-lock columns**, **#8 `candidate_pool_size`** — small removals; batch together.
- **#4 audit migration squash** — do in a migration-quiet window; verify no in-flight envs.
- **#7 severity-consistency** management command; **#9** partition-task monitoring.
- **#5 tri-state booleans**, **#6 `AdvisoryAccessGrant` FK** — need design + maintainer
  confirmation; **not** recommended as blind rewrites (low confidence per rubric).

## 7. Assumptions

- `ghsa_metadata` is genuinely read-nowhere: based on exhaustive `grep` (attribute access,
  templates, admin console, API, `to_payload`). Confidence 5, but a dynamic
  `getattr`/serializer path would not show up in grep.
- Confidence 3 findings (#5, #6, #7, #9) were **not** exhaustively read-traced; they are
  reported as candidates, not action items.

## 8. Scoring

`Priority = Impact × Confidence ÷ Effort`. Impact 1–5 (5 = correctness/security/data-loss),
Confidence 1–5 (5 = proven by code/tests), Effort 1–5 (1 = very small). High-impact,
high-confidence, low-effort work is prioritized; low-confidence rewrites are not recommended.
