# AdvisoryHub — Architecture

This document is the bottom-up implementation specification for
AdvisoryHub. It covers the **how**: the technology stack, the
application's internal structure, the architectural patterns it
relies on, the publication and GHSA pipelines in concrete terms, the
configuration surface, the operational story, and the testing
strategy. It is paired with [`requirements.md`](./requirements.md),
which describes the **what** — the actors, domain objects, and
functional requirements.

Per the scope chosen for the specification effort, this document
deliberately does **not** restate:

- The full data model field list (already implicit in the source and
  cited from [`invariant.md`](./invariant.md) where load-bearing).
- The full URL / API endpoint inventory (already captured by
  [`permissions.md` §9](./permissions.md#9-enforcement-surfaces) and
  the URLconf files themselves).

Cross-references point at the deep-dive documents in this folder.

---

## 1. Technology stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.14 | Project pins `>=3.14,<3.15` (see `pyproject.toml` / `.python-version`). |
| Web framework | Django 5.2 LTS | Server-rendered, HTMX-augmented. No SPA. |
| Database | PostgreSQL | The only supported backend — prod, dev, demo, and tests. Append-only audit triggers, the advisory no-delete trigger, `pg_trgm` indexes, and JSONB queries are Postgres-specific. |
| Async broker | Valkey (Redis-wire-compatible) | `redis://` URLs work unchanged. |
| Async runtime | Celery | Workers + beat scheduler. JSON serialiser only. |
| Authentication | `mozilla-django-oidc` | All authentication via OIDC. PKCE on by default. |
| Templating | Django templates + HTMX | `django_htmx` middleware; partial-update fragments on the admin console and advisory actions. |
| Markdown | `markdown-it-py` + `nh3` | Strict allowlist; rendered HTML never stored. |
| Git client | `git` CLI via `subprocess` | Used by the publication pipeline; argument lists only, never `shell=True`. |
| HTTP client (GHSA) | `requests` / `urllib3` | Through `ghsa.client`. |
| Metrics | `django-prometheus` | `PrometheusBeforeMiddleware` first, `PrometheusAfterMiddleware` last. |
| Error reporting | Sentry | Optional, enabled when `SENTRY_DSN` is set. |
| Lint / format | `ruff` | Config in `pyproject.toml`. |

The application is deliberately a server-rendered Django app: no
front-end build step, no SPA bundle, no GraphQL. Interactive
behaviour comes from HTMX partial updates against the same view
functions that render full pages.

---

## 2. Application layout

The Django project is split into focused apps; each owns a single
bounded concern and exposes a `services.py` as the canonical write
path. The agent-facing CLAUDE.md "App layout" diagram is the
canonical layout reference; the summary below restates each app's
responsibility in spec terms.

| App | Responsibility |
|---|---|
| `config` | Django project: split settings (`base / dev / prod / test`), URL roots, Celery app. |
| `common` | Cross-cutting helpers: healthchecks, JSON logging, request-id middleware, rate-limit decorators, Sentry init, text diff utilities. |
| `accounts` | Custom `User` (email-as-username), the OIDC backend, group sync, step-up authentication, the global `NotificationPreference` model. |
| `projects` | `Project`, `ProjectGitHubRepository`, the unsorted sentinel migration, and the PMI id validator. |
| `audit` | Append-only `AuditLogEntry`, the Postgres trigger migration, `redact_secrets`, the retention commands. |
| `advisories` | `Advisory`, `AdvisoryVersion`, `AdvisoryIntakeMetadata`, validators, identifiers, permissions, services (triage flow + the version-append helper), edit views, triage views, the state-/severity-faceted HTMX list view, and the shared `severity` parsing helper (denormalised level/score). |
| `access` | `AdvisoryAccessGrant`, `PendingInvitation`, grant / revoke / invite / redeem services, HTMX views. |
| `comments` | `AdvisoryComment`, `CommentVersion`, markdown rendering + sanitisation, mention extraction, list view. |
| `notifications` | Global preference + per-advisory override models, recipient resolver (`filter_for_event`), Celery email tasks (advisory events, triage events, comments, invitations). |
| `workflows` | `CveRequestTask`, `ReviewTask`, `OrphanCve`, and the services that drive their state machines. |
| `publication` | `PublicationTask`, `PublicationArtifact`, `PublicationRepositoryConfig`, OSV + CSAF builders + vendored schemas, the Git service, the Celery worker. |
| `admin_console` | The /admin/ sidebar shell and its section views (Inbox, CVEs, Publications, GHSA, Audit, Access log, Stats, Projects, Users, Groups, Invitations, Maintenance). Stats is the SLA-metrics page (`stats.py` computation + `views/stats.py`). The GHSA section (`views/ghsa.py`, feature-gated on `GHSA_FEATURE_ENABLED`) is the operations + observability dashboard described in §5.9. The Invitations section (`views/invitations.py`) lists outstanding (non-redeemed) `PendingInvitation` rows across all advisories with per-row re-send (refreshes the expiry window, INV-ACCESS-3) and cancel actions. |
| `api` | JSON API surface re-using the same `can_*` predicates as the web views. |
| `ghsa` | GitHub App client + JWT handling, PMI mirror, GHSA discovery / per-advisory sync, EF-CVE push, webhook ingest. |
| `intake` | The public report form (`/report/`), `HoneypotSubmission`, rate-limited project picker JSON. |
| `similarity` | LLM-assisted duplicate detection: `SimilarityCheck` / `SimilarityCandidate` task rows, the `AdvisoryFingerprint` cache, the Postgres prefilter, provider-agnostic LLM adapters (Anthropic / OpenAI-compatible), the owner-only HTMX panel, `backfill_fingerprints`. Dormant unless `SIMILARITY_CHECK_ENABLED`. |

Custom user model is set via `AUTH_USER_MODEL = "accounts.User"`.

---

## 3. Architectural patterns

### 3.1 Services as the only write path

Every app exposes a `services.py` module whose functions are the
canonical entry points for state-changing operations. Views and API
handlers call into the service layer; they never write to models
directly. This keeps:

- Authorisation checks and audit emissions co-located with the
  mutation.
- `transaction.atomic` blocks and `select_for_update` row locks
  applied in exactly one place per concept.
- Side-effect ordering (e.g. "Celery enqueue on `transaction.on_commit`")
  predictable across callers.

Notable services modules: `advisories.services` (triage flow,
`record_advisory_version`), `access.services` (grants, invitations,
redemption), `comments.services` (markdown rendering, mention
extraction, add/edit/redact), `workflows.services` (CVE and review
state machines), `publication.services` (`publish`, `retry`,
`mark_*`), `ghsa.services` (PMI sync, GHSA sync, refresh-for-publish,
EF-CVE push), `intake.services` (`create_submission`),
`audit.services` (`record`, `record_from_request`, `redact_secrets`).

### 3.2 Permission predicates as a single source

All capability checks come from `advisories/permissions.py`. The
file exposes `resolved_permission`, `can_view`, `can_edit`,
`can_comment`, `can_see_internal_comment`, `can_publish`,
`can_dismiss`, `can_request_cve`, `can_submit_for_review`,
`can_review`, `can_grant_access`, `can_triage`,
`can_flag_for_admin_routing`, `can_clear_admin_routing_flag`,
`can_change_project`, `can_revoke_approval` (and friends). Web views,
API endpoints, Celery tasks, and HTMX partials all import from the
same module. Templates do not import permissions modules — they
render decorated context the view computed. See
[`permissions.md` §9](./permissions.md#9-enforcement-surfaces) for
the per-surface enforcement map.

### 3.3 Audit at the service boundary

`audit.services.record` (programmatic) and
`audit.services.record_from_request` (carrying IP + User-Agent) are
the only writers of `AuditLogEntry`. Each service emits the
appropriate `Action` immediately after the successful mutation;
service code never builds an audit row by hand. All user/CI-supplied
strings flow through `audit.services.redact_secrets` before being
persisted ([INV-AUDIT-2](./invariant.md#inv-audit-2)). Git-token URLs
also go through `publication.git_service._redact`, which strips the
configured token in addition to whatever `redact_secrets` catches.

### 3.4 Append-only stores

Three tables are append-only by design:

- `AuditLogEntry` — application guard (`save` refuses
  `pk is not None`, `delete` raises) plus a Postgres trigger
  (`audit/migrations/0002_append_only_trigger.py`) that rejects
  `UPDATE` and `DELETE` even via raw SQL through the Django
  connection ([INV-AUDIT-1](./invariant.md#inv-audit-1)).
- `AdvisoryVersion` — application guard only
  ([INV-IMPL-5](./invariant.md#inv-impl-5)). Workflow tasks
  (`ReviewTask.version`, `PublicationTask.version`) `PROTECT`-FK
  into this table so even raw ORM cannot remove a pinned version.
- `CommentVersion` — application guard only
  ([INV-IMPL-3](./invariant.md#inv-impl-3)).

`Advisory` is non-deletable via a model-layer guard
(`Advisory.delete` and `AdvisoryQuerySet.delete` raise) and a
Postgres trigger
(`advisories/migrations/0003_advisory_no_delete_trigger.py`).
Dev-only seed-reset has an explicit
`_unsafe_dev_reset_bypass()` context manager that lowers
`session_replication_role` to `replica` for the transaction
duration so the trigger is bypassed; production code paths must not
call it.

### 3.5 State machines

The four lifecycle states plus three orthogonal status machines
(review, CVE, publication) are described in full in
[`advisory-lifecycle.md`](./advisory-lifecycle.md). Key
implementation notes:

- State is stored as a `TextChoices` enum field. Transitions are
  encapsulated in services functions whose names match the
  transition (`promote_triage_to_draft`, `dismiss_triage`,
  `submit_for_review`, `approve_review`, `request_changes`,
  `revoke_approval`, `withdraw_review`, `transition_cve_request`,
  `unassign_cve`, `mark_orphan_rejected`, `publish`, `retry`).
- Edits append `AdvisoryVersion`; the service
  `advisories.services.record_advisory_version` is the only path
  for `v(n+1)` and takes a `select_for_update` row lock on the
  advisory to serialise concurrent edits
  ([INV-CONCURRENCY-2](./invariant.md#inv-concurrency-2)).
- Editing an `approved` draft by a non-admin resets `review_status`
  ([INV-REVIEW-4](./invariant.md#inv-review-4)).
- Editing a `published` advisory sets `republish_required=True` and
  is reachable from the dashboard as "Re-publish". Such advisories
  also surface in the Admin Console under the Inbox "publish required"
  category and the Publication page's "Awaiting re-publication"
  section (GHSA-linked rows excluded — they auto-re-publish, INV-GHSA-3).

### 3.6 OIDC group sync

`accounts.auth.AdvisoryHubOIDCBackend.update_user` runs
`sync_groups_from_claims` on every login, replacing
`user.groups` with the set derived from the configured OIDC claim.
Claim values that do not look like SPNs (no `@`) are filtered out so
the Django `Group` table stays clean
([INV-OIDC-4](./invariant.md#inv-oidc-4)). `is_staff` and
`is_superuser` are set equal to admin-group membership on every
login ([INV-OIDC-3](./invariant.md#inv-oidc-3)); demotion in the IdP
removes Django-admin access on the next login. The OIDC scopes
requested are `openid email profile groups`.

OIDC config knobs: `OIDC_RP_CLIENT_ID/_SECRET`,
`OIDC_OP_*_ENDPOINT`, `OIDC_OP_LOGOUT_ENDPOINT`,
`OIDC_RP_SIGN_ALGO` (default `RS256`), `OIDC_USE_PKCE` (default
True, with `S256` challenge method), `OIDC_VERIFY_SSL` (True in
prod), `OIDC_GROUP_CLAIM`, `OIDC_ADMIN_GROUP`,
`OIDC_REQUIRE_EMAIL_VERIFIED` (default False — reject an *absent*
`email_verified` claim too; INV-OIDC-6). RP-initiated logout
uses `accounts.auth.provider_logout`; `OIDC_STORE_ID_TOKEN=True` so
the logout request can include `id_token_hint`.

### 3.7 Step-up authentication

`accounts.step_up` implements a session-scoped freshness check
(`request.session["step_up_auth_at"]` within
`STEP_UP_MAX_AGE_SECONDS`, default 300 s). The gated views call
`require_step_up_or_redirect(request, next_url=…)` — publish/withdraw,
GitHub App configuration, org-wide GHSA operations, CVE-push retries, and
the break-glass admin actions (forget user, ban/unban, maintenance toggle);
the full list is in [`permissions.md` §8](permissions.md#8-step-up-authentication).
If the timestamp is missing or stale, the user is bounced through a
`prompt=login&max_age=0` OIDC re-authentication via
`StepUpAuthRequestView` and `record_step_up_on_login` stamps the
fresh timestamp on the way back. An ordinary sign-in does not
satisfy the check — the `step_up_pending` flag is only set inside
the explicit step-up flow.

Authentication events are audited to the access log
([INV-AUDIT-5](./invariant.md#inv-audit-5)): `record_step_up_on_login`
(the sole `user_logged_in` receiver) writes `auth.login` for an ordinary
sign-in and `auth.step_up_completed` for a step-up re-auth; a `user_logged_out`
receiver in `accounts.signals` writes `auth.logout`; and
`accounts.auth.AdvisoryHubOIDCCallbackView` — wired ahead of the
`mozilla_django_oidc` include under the library's own callback URL name, so the
registered `redirect_uri` is unchanged — records `auth.login_failed` from
`login_failure()` (covering IdP-returned errors and rejected claims). All carry
the source IP/user-agent and surface on the Admin Console's Access log page.

### 3.8 Atomicity boundaries

The codebase uses three Django concurrency primitives:

- `transaction.atomic` wraps any operation that mutates more than one
  row or one table. Publication's final state flip, version append,
  task finalisation, and audit emissions share a single block
  ([INV-PUB-4](./invariant.md#inv-pub-4)).
- `Advisory.objects.select_for_update` is held by
  `record_advisory_version`, by `publish` (to serialise concurrent
  publishers), and by the publication worker's final block (to
  prevent the state flip from racing an edit).
- `transaction.on_commit` schedules Celery enqueues so a rolled-back
  caller transaction never leaves a queued task
  ([INV-PUB-5](./invariant.md#inv-pub-5)).

### 3.9 Data confidentiality and the database-compromise threat

Embargoed, pre-disclosure advisory content is the system's most sensitive
data. The headline threat is **an attacker who obtains the database
credentials and connects directly** (adjacent: a stolen backup/snapshot, a
malicious DBA, or a compromised app process). AdvisoryHub's answer is
**defense-in-depth on the database access path, not application-layer
encryption of content** ([INV-CONF-1](./invariant.md#inv-conf-1)).

Two distinct threats are routinely conflated under "encrypt the database":

- **Stolen media** (disk, snapshot, logical backup) — mitigated by
  encryption-at-rest (volume encryption or managed-DB TDE) and encrypted
  backups. Transparent to the app; no feature cost.
- **Stolen credentials → direct connection** (the headline threat) —
  encryption-at-rest does **nothing**: a client holding a valid password is a
  legitimate client, and the database decrypts for it.

Application-layer column encryption is **deliberately not used**. It would
defeat credential theft only if the key lived in a different trust domain than
the credential (a KMS/HSM); in this deployment the DB password and any
encryption key are injected into the same pod from the same secret store
(`config/settings/base.py`, `charts/advisoryhub/templates/secret-env.yaml`),
so both leak by the same path, and a compromised app process holds the key
regardless. It would also break load-bearing functionality: advisory search
(`summary`/`details`/`aliases` `__icontains` in `advisories/views.py` and
`api/views_advisories.py`) and the duplicate-detection prefilter
(`TrigramSimilarity` over `summary`/`details` plus JSONB `__contains` on
`aliases`/`affected` in `similarity/prefilter.py`,
[INV-SIM-4](./invariant.md#inv-sim-4)) both require plaintext, SQL-queryable
columns. The full plaintext archive lives in the append-only
`AdvisoryVersion.payload` ([INV-IMPL-5](./invariant.md#inv-impl-5)), so
encrypting content would also mean encrypting an immutable, `PROTECT`-FK'd log
where **key loss is unrecoverable data loss**.

Confidentiality of content at rest is therefore a **deployment-layer
responsibility**: restrict network reachability so only the app can reach
Postgres, prefer short-lived/IAM credentials over a static password, require
TLS (`sslmode=verify-full`), run the app under a least-privilege role, encrypt
backups and volumes, and enable database-level audit (pgaudit /
`log_connections`) — direct DB access bypasses the application audit log
([INV-AUDIT-1](./invariant.md#inv-audit-1)) entirely, so detection is the
compensating control. The operator checklist is in
[running-in-production.md §7](../operations/running-in-production.md#7-database-hardening-checklist).

### 3.10 Project data isolation and the authorization-bug threat

§3.9 addresses a *stolen credential* reaching the database. A different threat is
an **application authorization bug** — a new list view that forgets to call the
visibility chokepoint, or a detail/edit handler that fetches by id without a
permission check — leaking advisory content across the access boundary. That
boundary is `per-advisory ∪ per-project`: a user sees an advisory if they are on
its project's security team **or** hold an explicit `AdvisoryAccessGrant` (direct
or via a group), and an authenticated triage reporter is auto-granted viewer on
their own report.

**Schema- or database-per-project tenancy is deliberately not used.** It is a
poor fit for this boundary and this data model:

- The boundary is per-advisory as well as per-project, so a project schema would
  model only half of it — every cross-project grant would need cross-schema
  access.
- It would only move the bug: per-schema isolation needs per-schema DB roles, and
  *which roles a connection may assume* is decided by application code — the same
  trust domain as the bug. (A shared role with `search_path` switching isolates
  nothing.)
- It would fracture global infrastructure: the append-only audit timeline
  ([INV-AUDIT-1](./invariant.md#inv-audit-1)), the month-partitioned access log
  ([INV-AUDIT-5](./invariant.md#inv-audit-5)), `pg_trgm` search and the
  similarity prefilter all query across advisories.

The answer is **layered enforcement in the single schema**
([INV-CONF-2](./invariant.md#inv-conf-2)):

1. **One chokepoint.** `Advisory.objects.visible_to(user)` (wrapped by
   `advisories.permissions.visible_advisories`) is the single source of list
   visibility, shared by the HTML and JSON list endpoints.
2. **A CI guard.** `tests/test_authorization_matrix.py` enumerates every
   advisory-scoped route × role and asserts non-members are denied — a new
   endpoint that skips the check fails the suite by construction.
3. **A fail-closed backstop.** Postgres **row-level security** on
   `advisories_advisory` (with predicate-free deferring policies on its child
   tables) re-enforces `visible_to` on *every* query. This inverts the default
   from opt-in / **fail-open** (a query leaks unless it remembers to filter) to
   **fail-closed** (a query is filtered unless the principal is explicitly admin).

RLS keys on a per-request principal in session GUCs — `advisoryhub.user_id` and
`advisoryhub.is_admin` — set per request by `RowLevelSecurityMiddleware` (and
reset, fail-closed, when the response is done) and per Celery task / management
command by the `rls_principal` / `rls_system` context managers (`common/rls.py`).
A superuser or `BYPASSRLS` role is never subject to RLS, so the dev/CI bootstrap
role (a superuser) leaves it dormant — **enforcement is a production posture**
under the non-superuser app role (§7), validated in tests via `SET ROLE`. The
principal is trivially correct and lives apart from the permission logic it
protects, so a bug in that logic cannot widen what the database returns; an unset
principal matches no rows. The policy mirrors `visible_to` and is
**drift-tested** against it — RLS backstops the forgot-to-filter / IDOR class,
not a wrong predicate. The operator role model (single role +
`FORCE ROW LEVEL SECURITY`, or running the app under a separate non-owner login
role) is in
[running-in-production.md §7](../operations/running-in-production.md#7-database-hardening-checklist).

---

## 4. Publication pipeline

End-to-end implementation in
`publication/services.py` and `publication/tasks.py`, with the Git
layer in `publication/git_service.py`. The narrative below is the
companion to
[`advisory-lifecycle.md` §8](./advisory-lifecycle.md#8-publication-sequence-diagram).

### 4.1 Enqueue (`publication.services.publish`)

1. Wrapped in `@transaction.atomic`. The caller's user must pass
   `permissions.can_publish`; dismissed advisories are refused.
2. `Advisory.objects.select_for_update` locks the advisory row.
3. The lock-and-check pattern refuses a new attempt if any
   `PublicationTask(status ∈ {queued, running})` exists for the
   same advisory, raising `PublicationInProgress`
   ([INV-CONCURRENCY-1](./invariant.md#inv-concurrency-1)).
4. For GHSA-linked advisories, `ghsa.services.refresh_for_publish`
   runs before pinning. The refresh may append a new
   `AdvisoryVersion` if upstream returned changed fields.
5. The current latest `AdvisoryVersion` is read via
   `advisory_services.latest_version`. A `PublicationTask` row is
   created with `status=queued` pinning that version.
6. `PUBLICATION_EXPORT_STARTED` is audited.
7. `transaction.on_commit` schedules
   `publication.tasks.run_publication.delay(task.pk)`. A broker
   outage is non-fatal — the task remains `queued` and the admin
   console surfaces it so an operator can re-trigger after fixing
   the broker.

### 4.2 Worker (`publication.tasks.run_publication`)

Inside the Celery task body (no surrounding transaction — each step
either succeeds or marks the task `failed` and returns):

1. Load the task with `select_related("advisory", "version",
   "advisory__project")`. Return early if it's no longer
   queueable.
2. `services.mark_running(task)` flips status to `running`,
   increments `attempts`, stamps `started_at`, records
   `self.request.id` as `celery_task_id`.
3. Read `active_config()` (the currently active
   `PublicationRepositoryConfig`).
4. Build OSV via `publication.osv.build_osv(task.version)` and
   validate against the vendored schema; emit
   `PUBLICATION_OSV_GENERATED`. Same for CSAF
   (`publication.csaf.build_csaf` + `validate_csaf` +
   `PUBLICATION_CSAF_GENERATED`). When the pinned version carries an
   `assigned_cve_id`, additionally build a CVE Record
   (`publication.cve.build_cve` + `validate_cve` +
   `PUBLICATION_CVE_GENERATED`) — EF-assigned CVEs only, read from the
   pinned payload, never live data ([INV-VERSION-3](./invariant.md#inv-version-3)).
   On a *withdrawal* run (the pinned version carries `withdrawn_reason`) the
   CVE Record is built by `publication.cve.build_rejected_cve` instead — a
   `REJECTED` record whose `rejectedReasons` is the withdrawal reason — so the
   repo mirrors the cve.org rejection rather than re-asserting `PUBLISHED`
   ([INV-WITHDRAW](./invariant.md#inv-withdraw)).
   Validation is schema-based against the JSON Schemas vendored in
   `publication/schemas/` ([INV-PUB-6](./invariant.md#inv-pub-6)). Those schemas are
   pinned to upstream tags in `publication/schemas/SCHEMAS.VERSION` (OSV carries a
   local `ECL-` prefix patch), checksum-verified by `dev/check_vendored_assets.sh`,
   and version-tracked by the scoped self-hosted Renovate workflow (re-vendored by
   `dev/update_vendored_assets.py`; a schema bump auto-merges on green CI because
   `publication/tests` + the OSV ecosystem drift guard would catch a breaking change).
5. Persist `PublicationArtifact` rows for each kind (`osv`, `csaf`,
   and `cve` when present) via `update_or_create` keyed on
   `(task, kind)`, carrying the serialised path and the validated
   JSON content. This is the source of truth for the admin-console
   preview screens.
6. Hand the serialised documents to
   `publication.git_service.publish_files`.

### 4.3 Git layer (`publication.git_service.publish_files`)

Every step shells out to the `git` binary with explicit argument
lists (`subprocess.run`, never `shell=True`); there is no Python Git
library. Each invocation carries a wall-clock timeout (300 s for
clone/push, 60 s for local commands) — the only real hang protection,
since Celery time limits are not enforced under the worker's threads
pool. For each call:

1. `_git_env(config)` builds a per-call environment dict that
   *extends* `os.environ` (it never mutates it — that would race
   between concurrent publications under a threaded Celery pool;
   extending rather than replacing matters so the container
   entrypoint's nss_wrapper variables reach the git → ssh child
   processes): `GIT_TERMINAL_PROMPT=0` and the
   `GIT_AUTHOR_*`/`GIT_COMMITTER_*` identity from the config. When auth
   mode is `ssh`, `GIT_SSH` is pointed at a per-call wrapper script
   (generated into the scratch directory) that execs
   `ssh -i <key> -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o BatchMode=yes` —
   `GIT_SSH` is exec'd directly by git, whereas `GIT_SSH_COMMAND` is run
   through `/bin/sh`, which the production image doesn't have
   ([INV-SECRET-2](./invariant.md#inv-secret-2)).
2. A fresh `tempfile.TemporaryDirectory(prefix="advisoryhub-pub-")`
   ([INV-PUB-1](./invariant.md#inv-pub-1)).
3. `_embed_token(config)`: if auth mode is `token` and the URL is
   HTTPS, rewrites it to
   `https://x-access-token:$PUB_REPO_TOKEN@…`. The rewritten URL is
   only used as a `git clone` argument; it is never persisted,
   logged, or audited.
4. `git clone --depth 1 --single-branch --branch <branch>` — shallow
   clone ([INV-PUB-3](./invariant.md#inv-pub-3)).
5. `_write_files(workdir, files)` writes each `WrittenFile` and
   returns whether anything changed. Idempotent on content: if both
   the OSV and the CSAF are byte-identical to what is already on
   the branch, no commit is created and the function returns
   `PublishResult(commit_sha=HEAD, …)`.
6. Otherwise `git add`, then
   `git -c commit.gpgsign=false -c tag.gpgsign=false commit` with the
   deterministic message `Publish advisory <advisory_id>` (the bot
   must never sign commits — the deploy key/token is the trust
   signal; a host-wide `commit.gpgsign=true` would otherwise abort
   the commit), then `git push origin HEAD:<branch>`. A non-zero
   exit from any step — including rejected pushes — raises
   `GitPublicationError`.
7. All raised error strings are built from the failing subcommand's
   name and git's own output — never from the argument list, which
   may embed the token — and flow through `_redact(str, config)`
   which calls `audit.services.redact_secrets` and then explicitly
   strips the configured token, so an error message that somehow
   surfaces a URL with embedded credentials still leaves the
   redacted form on the way out.

### 4.4 Atomic finalisation

Back in the worker, on a clean `publish_files` return:

```python
with transaction.atomic():
    advisory = Advisory.objects.select_for_update().get(pk=task.advisory_id)
    advisory.state = State.PUBLISHED
    if advisory.published_at is None:
        advisory.published_at = timezone.now()
    advisory.republish_required = False
    advisory.save(...)
    services.mark_succeeded(task, commit_sha=...)
    record(action=Action.ADVISORY_PUBLISHED, ...)
    record(action=Action.PUBLICATION_EXPORT_COMPLETED, ...)
```

`PUBLICATION_GIT_COMMIT` and `PUBLICATION_GIT_PUSH` are audited
*before* the atomic block, immediately after the push returns
clean. The state flip, task finalisation, and the two terminal
audit rows live inside the atomic block
([INV-PUB-4](./invariant.md#inv-pub-4)). The post-commit
`advisory_published` notification is enqueued best-effort.

**Withdrawal mode.** The pipeline doubles as the *withdrawal* path
([INV-WITHDRAW](./invariant.md#inv-withdraw)): a pinned version carrying
`withdrawn_reason` exports OSV/CSAF *with* the withdrawn marker (OSV
`withdrawn` timestamp; a CSAF withdrawal `revision_history` entry + document
note), re-exports any assigned CVE record as a `REJECTED` record
(`build_rejected_cve`, `rejectedReasons` = the withdrawal reason — mirroring
cve.org), and the finalisation branch flips the advisory to `dismissed`
(`dismissed_from_state=published`) instead of `published`, orphaning any
assigned CVE — no new task type, the end state is keyed off the payload. The
document is updated in place, never deleted; a failed withdrawal push leaves
the advisory `published` with a retryable `PublicationTask`. The post-commit
`advisory_published` notification is skipped for a withdrawal.

### 4.5 Failure handling

Any of {`OsvValidationError`, `CsafValidationError`,
`GitPublicationError`, unexpected `Exception`} routes through
`_fail(task, error=..., action=...)`:

- `services.mark_failed(task, error=…)` flips status to `failed`,
  stamps `finished_at`, truncates the redacted error to 8000
  characters into `last_error`.
- The appropriate audit `Action` is recorded; the redacted
  `task.last_error` is passed in `metadata["error"]`.
- A best-effort `publication_export_status` notification is queued.
- `Advisory.state` is **unchanged**
  ([INV-LIFECYCLE-3](./invariant.md#inv-lifecycle-3)).

A retry is a brand-new `PublicationTask` pinned to the current
latest version, not a re-run of the failed row.

**Stale-task reaper.** The `_fail` path requires a live worker. Two loss
modes never reach it: a worker hard-killed after the run started (hard
`time_limit` SIGKILL, OOM kill, pod eviction) leaves the row `running` —
the redelivered message no-ops against the QUEUED/FAILED entry guard —
and a broker outage at enqueue time (`common.enqueue.safe_enqueue`
swallows the error) leaves it `queued` with no Celery message at all.
Either row wedges the in-flight guard
([INV-CONCURRENCY-1](./invariant.md#inv-concurrency-1)) forever. The
beat-scheduled reaper (`publication.reap_stale_publication_tasks`, §6.2)
bounds both: it fails `running` rows older than
`PUB_TASK_STALE_RUNNING_AFTER_SECONDS` (default 1800 s, comfortably past
the 660 s hard `time_limit`) and `queued` rows older than
`PUB_TASK_STALE_QUEUED_AFTER_SECONDS` (default 7200 s, past the 3600 s
broker `visibility_timeout` so a delayed redelivery always wins first).
Each reap is a per-row compare-and-set under
`select_for_update(skip_locked=True)` — a row finalised concurrently
falls out of the filter and is never clobbered — and routes through the
same `mark_failed` / audit (`PUBLICATION_TASK_REAPED`) / best-effort
notification surface as `_fail`, never touching `Advisory.state`
([INV-PUB-7](./invariant.md#inv-pub-7)).

---

## 5. GHSA integration

The GHSA app makes AdvisoryHub a *bridge* over GitHub's Security
Advisory product for a curated set of repos.

### 5.1 Authentication & installation

AdvisoryHub authenticates to GitHub as a registered **GitHub App**
with `repository_security_advisories: read & write` (plus the
default `metadata: read`). The App is installed per-repo by
Eclipse org admins. The single load-bearing secret is the App's
private key, sourced from either `GITHUB_APP_PRIVATE_KEY_PATH`
(a file on disk; preferred in prod) or `GITHUB_APP_PRIVATE_KEY`
(inline; dev fallback). The key is never persisted to the DB and
never logged; the audit redactor catches it if it ever surfaces.

The `GitHubAppInstallation` table tracks each installation's
`installation_id`, `account_login`, account type, suspended status,
and the App slug it's installed as. It is populated via the
`discover_github_installations` management command or the first
inbound `installation.created` webhook.

### 5.2 PMI repo mirror

`projects.ProjectGitHubRepository` mirrors the `(owner, name)`
pairs PMI declares for each Eclipse Foundation project. The mirror
is refreshed by `ghsa.tasks.run_pmi_repo_sync`, scheduled by Celery
beat every `PMI_SYNC_INTERVAL_HOURS` hours (default 6). The PMI
sync is the only way new repos appear; repos that disappear from
PMI are soft-removed (kept for audit) rather than deleted. Each
sync emits a `PMI_PROJECT_REPOS_SYNCED` audit row. Each row also caches its
GitHub private-vulnerability-reporting status (`pvr_enabled` / `pvr_checked_at`,
refreshed by `refresh_pvr_status`), which gates the "Move to GHSA" action (§5.10).

### 5.3 GHSA discovery & per-advisory sync

GHSA discovery runs on demand — `ghsa.services.sync_ghsas_for_project`
for one project or `sync_ghsas_for_all_projects` for the whole org;
the admin console exposes both — **and** on a slow beat schedule
(`run_scheduled_ghsa_discovery`, §6.2) as a backstop for missed
`repository_advisory.reported` webhooks. Discovery walks each
`(owner, name)` in the project's repo mirror, lists GHSAs (all upstream
states: `draft,triage,published,closed,withdrawn`), and creates or updates
`Advisory(kind=ghsa_linked)` rows whose `ghsa_id` is uniquely
mapped ([INV-ID-2](./invariant.md#inv-id-2)). A newly-created row's `state`
mirrors GitHub's `ghsa_state` — `triage` when the GHSA is still in triage
upstream (a private report not yet accepted into a draft), else `draft`
([INV-GHSA-3](./invariant.md#inv-ghsa-3)). A run is recorded as
a `GhsaSyncRun` with counts and last error.

Both sync functions are `transaction.atomic`, and that atomicity is
load-bearing for run-row truthfulness: the `running` row commits only
together with its finalisation, so an interrupted sync (worker
hard-kill or an escaping exception) rolls the row back instead of
stranding a forever-"Running" entry in the run history. `GhsaSyncRun`
therefore needs no stale-row reaper — unlike `GhsaCvePushTask`
(§5.4, [INV-GHSA-2](./invariant.md#inv-ghsa-2)).

Per-advisory sync (`sync_single_ghsa`) refreshes one advisory from
GitHub. When upstream payload-visible fields change,
`AdvisoryVersion` v(n+1) is appended and
`GHSA_METADATA_FETCHED` is audited; heartbeat syncs (no changes)
only refresh `ghsa_metadata_synced_at` and do not append a version
([INV-VERSION-1](./invariant.md#inv-version-1)).

### 5.4 EF-CVE push

When an EF-assigned CVE is reserved on a GHSA-linked advisory,
`ghsa.services.enqueue_cve_push` creates a `GhsaCvePushTask` that
`ghsa.tasks.run_cve_push` executes: the task PATCHes the upstream
GHSA's `cve_id` to the EF value. Outcomes are audited
(`GHSA_CVE_PUSH_REQUESTED`, `GHSA_CVE_PUSH_SUCCEEDED`,
`GHSA_CVE_PUSH_FAILED`). If a subsequent sync sees the GHSA already
carrying a *different* CVE, AdvisoryHub never overwrites its own
value; instead `GHSA_CVE_CONFLICT_DETECTED` is emitted and
`ghsa_cve_conflict_*` columns are populated so an admin can
reconcile manually.

`run_cve_push` has no `acks_late`, so a worker hard-killed mid-push
leaves the task `running` with no redelivery — and the advisory's
CVE-push badge stuck at "Pending". The beat-scheduled
`ghsa-cve-push-reaper` (§6.2, [INV-GHSA-2](./invariant.md#inv-ghsa-2))
bounds both that and broker-stranded `queued` rows, flipping them to
`failed` (audited as `GHSA_CVE_PUSH_REAPED`) and correcting the
advisory badge — guarded so it never clobbers a status belonging to a
newer push task.

### 5.5 Webhook ingest

Inbound webhook deliveries are HMAC-verified against
`GITHUB_APP_WEBHOOK_SECRET` and deduplicated by delivery id via
the `WebhookDelivery` table. Recognised events route to handlers in
`ghsa.webhooks`; unrecognised events are logged as
`GHSA_WEBHOOK_REJECTED` and dropped. A `repository_advisory` event for an
*existing* advisory always refreshes and reacts; for an *unknown* GHSA on a
PMI-mirrored repo it auto-creates a row on
`published`/`updated`/`edited`/`reopened`/`reported` — `reported` is GitHub's
private-vulnerability-report event, so the new row mirrors GitHub's triage state
(§5.3, [INV-GHSA-3](./invariant.md#inv-ghsa-3)). Installation lifecycle events
(`installation.created`, `suspended`, `unsuspended`,
`deleted`) update `GitHubAppInstallation` rows accordingly.

### 5.6 Refresh-for-publish

Before publishing a GHSA-linked advisory,
`publication.services.publish` calls
`ghsa.services.refresh_for_publish`, which pulls the latest GHSA
metadata. If the GHSA itself is not published, is missing upstream,
or has an outstanding CVE conflict, the refresh raises
`PermissionDenied` and publication is aborted with a 4xx response
in the calling view. On success, any payload-visible drift is
appended as a new `AdvisoryVersion` before the publication task
pins the version.

### 5.7 Inbound lifecycle reactions

GHSA-linked advisory lifecycle is **inbound-only**
([INV-GHSA-3](./invariant.md#inv-ghsa-3)): AdvisoryHub mirrors GitHub and never
writes lifecycle state back. After an *observing* sync — the webhook dispatcher,
the manual single-sync, or a freshly-created advisory —
`ghsa.services.react_to_ghsa_state` inspects the result and reacts.
`refresh_for_publish` deliberately does **not** react, so
`publish → refresh → sync → publish` cannot recurse.

**Triage mirror.** A GHSA-linked advisory created while the GHSA is in triage
upstream lands in `state=triage` as a read-only mirror (§5.3) — no human
promote/dismiss/flag (`can_triage` / `can_flag_for_admin_routing` return `False`;
it is kept out of the admin-console Inbox). When GitHub accepts the report into a
draft (`ghsa_state` `triage` → `draft`), the reaction flips the row `triage` →
`draft` (forward-only state flip, no version appended) and the standard workflow
takes over.

**Auto-publish.** When the linked GHSA is `published` and the AdvisoryHub
advisory is in `draft` or `triage` (a GHSA published straight from triage
upstream), the reaction enqueues `ghsa.tasks.run_ghsa_auto_publish`,
which calls `publish(system=True)` — exporting OSV/CSAF/CVE through the normal
pipeline, skipping only the human `can_publish` gate (the decision is GitHub's).
It is idempotent (keyed off the current state; `publish()`'s in-flight lock
dedupes a webhook-vs-reconcile double fire) and best-effort (a gating refusal —
CVE conflict, missing upstream, concurrent run — is logged and skipped; a real
export failure surfaces as a failed `PublicationTask`). Controlled by
`GHSA_AUTO_PUBLISH_ENABLED` (default on).

**Auto-dismiss / auto-withdraw.** When the linked GHSA is closed, withdrawn, or
deleted (404), the reaction mirrors it: a `draft`/`triage` advisory is dismissed
(`dismiss_advisory`), and a `published` one is **withdrawn**
(`withdraw_advisory`, [INV-WITHDRAW](./invariant.md#inv-withdraw)) — the OSV/CSAF
are re-exported marked withdrawn (the withdrawal `publish` skips
`refresh_for_publish`, since the GHSA is gone). An advisory holding an EF CVE is
left flagged for an admin instead — orphaning a CVE is a CNA action the system
won't take. The periodic reconcile (§6.2) sweeps `draft`/`triage`/`published` so
withdrawals/deletions GitHub doesn't webhook are still caught.

### 5.8 Feature gate

The integration is fronted by the `GHSA_FEATURE_ENABLED` boolean
flag. With the flag off, GHSA views and tasks short-circuit; the
admin console hides the GHSA section (the sidebar link is gated by the
`common.context_processors.ghsa_feature` context processor, and every
GHSA action endpoint re-checks the flag server-side).

### 5.9 Admin console GHSA operations

The Admin Console **GHSA** section (`/admin/ghsa/`, `admin_console/views/ghsa.py`,
admin-only via `can_review`) is a read-only dashboard (`INV-AUTH-1` — it only
displays) that surfaces the integration's bookkeeping tables and offers the
maintenance actions that already live in `ghsa.views`. The actions POST to
`ghsa:` endpoints which re-affirm authorization, step-up, rate limits, and the
feature flag; the org-wide ones reuse the existing beat tasks / services and
share their broker-offline inline fallback:

- **Sync all GHSAs** (`ghsa:sync-all` → `run_ghsa_sync_all`), **Run discovery now**
  (`ghsa:discover` → `run_scheduled_ghsa_discovery`), **Reconcile now**
  (`ghsa:reconcile` → `reconcile_ghsa_linked_advisories`), **Refresh all PMI repo
  mirrors** (`ghsa:sync-all-pmi` → `run_pmi_repo_sync`) — manual triggers for the
  §6.2 backstops.
- **Retry all failed CVE pushes** (`ghsa:retry-all-cve-pushes` →
  `ghsa.services.retry_all_failed_cve_pushes`) — the bulk counterpart of the
  per-row retry (`ghsa:retry-cve-push`): resets every `failed` `GhsaCvePushTask`
  to `queued` and re-fans `run_cve_push`. No new audit action — each push records
  its own `GHSA_CVE_PUSH_*` outcome, as the single retry already does.
- **Catch up now** (`ghsa:catch-up-webhooks`) — webhook payload bodies are
  deliberately not persisted (§5.5), so a failed `WebhookDelivery` cannot be
  replayed directly; this re-runs reconcile + discovery, the documented poll
  backstop for state GitHub failed to deliver.
- **Rescan installations** (`ghsa:rescan-installations`) — surfaced from the
  GitHub-App config page (`ghsa:connect`, linked from the section header).

The observability tables show failed `GhsaCvePushTask` rows (with per-row + bulk
retry), recent `GhsaSyncRun` history, recent `WebhookDelivery` history, and the
registered `GitHubAppInstallation` rows. No new lifecycle write to GitHub is
introduced — every operation is a pull/sync or the already-sanctioned CVE push
([INV-GHSA-3](./invariant.md#inv-ghsa-3)).

### 5.10 Move to GHSA (outbound create)

When a vulnerability is filed as a **native** AdvisoryHub report (`triage` or
`draft`) that should have been a private vulnerability report on GitHub, an owner
can **move it to GHSA** ([INV-GHSA-4](./invariant.md#inv-ghsa-4)). This is the one
outbound *create* in the bridge (alongside the CVE push, the only other outbound
write):

- **Client.** `GitHubAppClient.create_repository_advisory` (`POST
  /repos/{owner}/{repo}/security-advisories`, covered by
  `repository_security_advisories: write`) and
  `get_private_vulnerability_reporting` (`GET …/private-vulnerability-reporting`,
  covered by `metadata: read`).
- **PVR cache.** `ProjectGitHubRepository.pvr_enabled` / `pvr_checked_at` cache
  each active repo's private-vulnerability-reporting status, refreshed by
  `ghsa.services.refresh_pvr_status`. The cheap `can_move_to_ghsa` UI gate reads
  the cache; the move picker (`advisory_move_to_ghsa_modal`) refreshes it live
  before listing PVR-enabled repos.
- **Service.** `ghsa.services.move_advisory_to_ghsa` (`@transaction.atomic`,
  `select_for_update`) re-checks `can_move_to_ghsa`, validates the target repo is
  an active repo of the advisory's **own** project (so the project never changes,
  [INV-GHSA-1](./invariant.md#inv-ghsa-1)) with PVR enabled *right now*, builds the
  create body from the report (`build_repository_advisory_payload` — `summary` +
  `description` always, plus best-effort CWEs / CVSS vector / `vulnerabilities`
  mapped from OSV `affected`, plus `cve_id` when one is assigned), calls the
  client, then flips `kind` `native`→`ghsa_linked` in place, sets
  `ghsa_id`/`ghsa_owner`/`ghsa_repo`, runs the initial `sync_single_ghsa` +
  `react_to_ghsa_state` to mirror upstream content/state, appends one
  `AdvisoryVersion`, clears any pending review/reassignment, and audits
  `ADVISORY_MOVED_TO_GHSA`.
- **View.** `advisories.views.advisory_move_to_ghsa` — a normal full-page POST
  (so step-up's OIDC redirect works), rate-limited and step-up-gated; the modal is
  HTMX-loaded for the live PVR picker.

After the move the advisory is GHSA-linked and follows the inbound-only lifecycle
([INV-GHSA-3](./invariant.md#inv-ghsa-3)).

---

## 6. Background jobs

### 6.1 Celery configuration

`config/celery.py` instantiates the Celery app with
`config_from_object("django.conf:settings", namespace="CELERY")`
and `autodiscover_tasks()`. Settings:

| Setting | Default | Notes |
|---|---|---|
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Valkey or Redis. |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/1` | Separate DB index from the broker. |
| `CELERY_TASK_SERIALIZER` | `json` | Hard requirement — no pickle. |
| `CELERY_RESULT_SERIALIZER` | `json` | Same. |
| `CELERY_ACCEPT_CONTENT` | `["json"]` | Same. |
| `CELERY_TIMEZONE` | `TIME_ZONE` (default UTC) | — |
| `CELERY_TASK_ALWAYS_EAGER` | False | Forced True in `config.settings.test`. |
| `CELERY_TASK_EAGER_PROPAGATES` | True | Errors raised in tests, not swallowed. |
| `CELERY_TASK_IGNORE_RESULT` | True | Results are never read (outcomes live on `PublicationTask`); keeps the result backend empty. |
| `CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP` | True | Pins the resilient behaviour across the Celery 6 default flip. |
| `CELERY_BROKER_TRANSPORT_OPTIONS` | `{"visibility_timeout": 3600}` | Redelivery window for the Redis/Valkey transport; must exceed the longest task. `PUB_TASK_STALE_QUEUED_AFTER_SECONDS` must in turn exceed this window (§6.2). |
| `run_publication` task | `acks_late`, `reject_on_worker_lost`, `soft_time_limit=600`, `time_limit=660` | At-least-once for the durable publication task; a hung git push fails-and-is-retryable rather than running until the visibility window. A worker lost *after* the run starts leaves the row `running`; the beat-scheduled reaper recovers it (§6.2, [INV-PUB-7](./invariant.md#inv-pub-7)). |

Run a worker with `celery -A config worker -l info`. Run beat with
`celery -A config beat`.

**Ops:** the broker (db0), result backend (db1) and cache (db2) share one Valkey
instance. Run it with `--maxmemory-policy noeviction` (the default) so an eviction
can never silently drop broker messages or rate-limit/maintenance keys, and in prod
use `rediss://` (TLS) + AUTH. `/readyz` can probe the broker when
`READYZ_INCLUDE_BROKER=True` (off by default — see §7.3).

### 6.2 Beat schedule

Eight periodic jobs are registered in `config/settings/base.py`:

```python
CELERY_BEAT_SCHEDULE = {
    "pmi-repo-mirror": {
        "task": "ghsa.tasks.run_pmi_repo_sync",
        "schedule": timedelta(hours=PMI_SYNC_INTERVAL_HOURS),
    },
    "access-log-partition-maintenance": {
        "task": "audit.tasks.maintain_access_log_partitions",
        "schedule": timedelta(days=1),
    },
    "backlog-gauge-refresh": {
        "task": "audit.tasks.refresh_backlog_gauges",
        "schedule": timedelta(seconds=60),
    },
    "security-roster-sync": {
        "task": "projects.tasks.run_roster_sync",
        "schedule": timedelta(hours=PMI_ROSTER_SYNC_INTERVAL_HOURS),
    },
    "publication-task-reaper": {
        "task": "publication.reap_stale_publication_tasks",
        "schedule": timedelta(minutes=10),
    },
    "similarity-check-reaper": {
        "task": "similarity.reap_stale_similarity_checks",
        "schedule": timedelta(minutes=10),
    },
    "ghsa-cve-push-reaper": {
        "task": "ghsa.tasks.reap_stale_cve_push_tasks",
        "schedule": timedelta(minutes=10),
    },
    "ghsa-linked-reconcile": {
        "task": "ghsa.tasks.reconcile_ghsa_linked_advisories",
        "schedule": timedelta(hours=GHSA_SYNC_INTERVAL_HOURS),
    },
    "ghsa-discovery": {
        "task": "ghsa.tasks.run_scheduled_ghsa_discovery",
        "schedule": timedelta(hours=GHSA_DISCOVERY_INTERVAL_HOURS),
    },
}
```

`backlog-gauge-refresh` re-reads the operator queue depths and `.set()`s the
`advisoryhub_backlog` Prometheus gauge (see §8.3); it runs in the worker so the
series lands on the worker's metrics exporter.

`access-log-partition-maintenance` creates the upcoming month's
`AccessLogEntry` partition and drops months older than
`AUDIT_ACCESS_LOG_RETENTION_DAYS` (default 90); it no-ops when
`AUDIT_ACCESS_LOG_RETENTION_ENABLED` is False (see §8.6, [INV-AUDIT-5](./invariant.md#inv-audit-5)).

`security-roster-sync` mirrors each project's Eclipse security team into
`SecurityTeamRosterEntry` rows and pre-provisions notification-only shadow
users (`User.is_provisioned=True`) so `@team` mentions and team notifications
reach members who have never logged in. It uses the **authenticated** Eclipse
API (`projects/eclipse_api.py`, OAuth2 client-credentials) to resolve member
emails the public PMI feed hides, and **no-ops unless `PMI_ROSTER_SYNC_ENABLED`
is set** (default off). Shadow users hold no authorization ([INV-OIDC-5](./invariant.md#inv-oidc-5)); reach
is notification-only ([INV-ROSTER-1](./invariant.md#inv-roster-1)).

`publication-task-reaper` fails `PublicationTask` rows orphaned in
`running` (worker hard-killed mid-run: `time_limit` SIGKILL, OOM kill, pod
eviction) or `queued` (enqueue swallowed by `safe_enqueue` during a broker
outage), so the in-flight guard ([INV-CONCURRENCY-1](./invariant.md#inv-concurrency-1)) can never block
publishing forever. Thresholds: `running` after
`PUB_TASK_STALE_RUNNING_AFTER_SECONDS` (default 1800 s — past the 660 s
hard `time_limit`, so the row cannot belong to a live execution) from
`started_at`; `queued` after `PUB_TASK_STALE_QUEUED_AFTER_SECONDS`
(default 7200 s — past the 3600 s broker `visibility_timeout`, so a
delayed redelivery wins first) from `created_at`. It never touches
`Advisory.state` ([INV-LIFECYCLE-3](./invariant.md#inv-lifecycle-3)); see §4.5 and [INV-PUB-7](./invariant.md#inv-pub-7).

`similarity-check-reaper` is the same janitor for `SimilarityCheck`
rows, which otherwise wedge `request_check`'s in-flight guard and the
panel's re-run button forever (the view swallows
`SimilarityCheckInProgress`, so the panel just shows "pending"). Same
mechanism as §4.5; thresholds
`SIMILARITY_CHECK_STALE_RUNNING_AFTER_SECONDS` (default 1800 s — past
the 360 s hard `time_limit`) and
`SIMILARITY_CHECK_STALE_QUEUED_AFTER_SECONDS` (default 7200 s). Reaping
is DB-only — no LLM egress ([INV-SIM-2](./invariant.md#inv-sim-2) unaffected) — so it runs even
while `SIMILARITY_CHECK_ENABLED` is off; recovery after a reap is the
panel's existing re-run button. See [INV-SIM-5](./invariant.md#inv-sim-5).

`ghsa-cve-push-reaper` is the third janitor, for `GhsaCvePushTask`
rows. Unlike the previous two it is display truth, not deadlock
recovery: nothing blocks (there is no in-flight guard), but a worker
hard-killed mid-push (`run_cve_push` has no `acks_late` → no
redelivery) leaves the task `running` forever and the advisory's
CVE-push badge stuck at "Pending". Thresholds:
`GHSA_CVE_PUSH_STALE_RUNNING_AFTER_SECONDS` (default 1800 s — a push
is one GitHub API call bounded by the client's 10 s/30 s timeouts)
from `started_at`, `GHSA_CVE_PUSH_STALE_QUEUED_AFTER_SECONDS`
(default 7200 s) from `created_at`. The advisory-badge flip is
guarded against newer push tasks (§5.4). DB-only — no GitHub egress —
so it runs even while `GHSA_FEATURE_ENABLED` is off. `GhsaSyncRun`
needs no reaper (§5.3 — atomic create+finalise). See [INV-GHSA-2](./invariant.md#inv-ghsa-2).

`ghsa-linked-reconcile` is the inbound-lifecycle poll backstop
([INV-GHSA-3](./invariant.md#inv-ghsa-3)): every `GHSA_SYNC_INTERVAL_HOURS`
(default 6) it re-syncs each non-terminal (draft/triage/published) GHSA-linked
advisory **that already exists** via `sync_single_ghsa` and runs
`react_to_ghsa_state`, mirroring the current GitHub state — promoting a now-
accepted triage row to draft, auto-publishing a now-`published` draft/triage row,
auto-dismissing a closed/withdrawn/deleted draft/triage row, and auto-*withdrawing*
a published one ([INV-WITHDRAW](./invariant.md#inv-withdraw)). It exists because
GitHub does **not** reliably emit `repository_advisory` webhooks for
withdrawal/closure/deletion (and never for deletion), so the webhook path alone
would miss them. It does **not** discover new GHSAs. Per-advisory failures are
logged and skipped; no-ops while `GHSA_FEATURE_ENABLED` is off.

`ghsa-discovery` is the *discovery* backstop: every
`GHSA_DISCOVERY_INTERVAL_HOURS` (default 24 — heavier than reconcile, as it lists
every repo) `run_scheduled_ghsa_discovery` runs `sync_ghsas_for_all_projects`,
auto-creating rows for GHSAs not yet mirrored. It catches `repository_advisory.reported`
webhooks GitHub may not deliver (a newly-reported GHSA enters triage upstream and
is mirrored as a triage row). On-demand discovery from the admin console stays the
primary path; each run is recorded as a `GhsaSyncRun`. No-ops while
`GHSA_FEATURE_ENABLED` is off.

### 6.3 Task inventory

| App | Task | Purpose |
|---|---|---|
| `publication` | `run_publication` | Build → validate → push → flip state. |
| `publication` | `reap_stale_publication_tasks` | Beat-scheduled janitor: fails `PublicationTask` rows orphaned in queued/running ([INV-PUB-7](./invariant.md#inv-pub-7)). |
| `similarity` | `run_similarity_check` | Prefilter → fingerprint → LLM judge → persist top-5 potential duplicates. `rate_limit="6/m"` absorbs GHSA bulk-sync bursts. |
| `similarity` | `reap_stale_similarity_checks` | Beat-scheduled janitor: fails `SimilarityCheck` rows orphaned in queued/running ([INV-SIM-5](./invariant.md#inv-sim-5)). |
| `notifications` | `send_advisory_event_email` | Lifecycle events (created, submitted for review, published, publication export status). |
| `notifications` | `send_comment_email` | Comment + mention notifications. |
| `notifications` | `send_comment_mention_email` | Delta @-mentions added by a comment *edit* (including newly-mentioned `@team` shadow roster members); visibility re-checked at send time. |
| `notifications` | `send_advisory_triage_event_email` | Triage-flow events to the project security team or admins. |
| `notifications` | `send_intake_event_email` | Legacy no-op to drain queues from before the triage refactor. |
| `notifications` | `send_invitation_email` | Invitation delivery. |
| `ghsa` | `run_pmi_repo_sync` | Beat-scheduled PMI mirror refresh. |
| `ghsa` | `run_ghsa_sync_project` | On-demand GHSA discovery for one project. |
| `ghsa` | `run_ghsa_sync_all` | On-demand GHSA discovery for the whole org. |
| `ghsa` | `run_scheduled_ghsa_discovery` | Beat-scheduled GHSA discovery backstop (org-wide): auto-creates rows for GHSAs not yet mirrored, catching missed `repository_advisory.reported` webhooks ([INV-GHSA-3](./invariant.md#inv-ghsa-3)). No-op unless `GHSA_FEATURE_ENABLED`. |
| `ghsa` | `run_single_ghsa_sync` | Per-advisory GHSA metadata refresh (advisory-page Sync button); reacts to the observed state ([INV-GHSA-3](./invariant.md#inv-ghsa-3)). |
| `ghsa` | `run_ghsa_auto_publish` | System-initiated `publish(system=True)` when GitHub publishes a GHSA-linked draft/triage row ([INV-GHSA-3](./invariant.md#inv-ghsa-3)). |
| `ghsa` | `reconcile_ghsa_linked_advisories` | Beat-scheduled poll backstop: re-syncs already-known draft/triage/published GHSA-linked advisories and mirrors GitHub state — triage→draft promotion / auto-publish / auto-dismiss / auto-withdraw ([INV-GHSA-3](./invariant.md#inv-ghsa-3), [INV-WITHDRAW](./invariant.md#inv-withdraw)). |
| `ghsa` | `run_cve_push` | Push EF-assigned CVE to a linked GHSA. |
| `ghsa` | `reap_stale_cve_push_tasks` | Beat-scheduled janitor: fails `GhsaCvePushTask` rows orphaned in queued/running and corrects the advisory's CVE-push badge ([INV-GHSA-2](./invariant.md#inv-ghsa-2)). |
| `ghsa` | `process_webhook` | Applies a signature-verified webhook delivery (per-advisory refresh or auto-create) off the request thread. |
| `audit` | `maintain_access_log_partitions` | Beat-scheduled `AccessLogEntry` partition create-ahead + drop-expired. |
| `audit` | `refresh_backlog_gauges` | Beat-scheduled refresh of the `advisoryhub_backlog` Prometheus gauge from live queue depths. |
| `projects` | `run_roster_sync` | Beat-scheduled security-team roster sync (shadow-user provisioning); no-op unless `PMI_ROSTER_SYNC_ENABLED`. |

Idempotency story:

- `run_publication` is short-circuited when the task is no longer
  in a queueable state; success / failure is terminal per-row, and
  the file write is idempotent on content.
- `reap_stale_publication_tasks`, `reap_stale_similarity_checks`, and
  `reap_stale_cve_push_tasks` are idempotent by construction: the
  candidate predicate is status+staleness, reaped rows leave the set,
  and each reap is a per-row compare-and-set — overlapping runs
  `skip_locked` each other rather than double-reaping.
- `run_similarity_check` uses the same queued/failed-only guard, and
  the fingerprint cache is keyed on a content hash, so a re-delivered
  task never duplicates LLM spend for unchanged content.
- GHSA per-advisory sync writes a new version only on payload
  change.
- Notification tasks recompute recipients at send time, so an
  enqueued-then-revoked grant produces no email.

### 6.4 Duplicate-detection pipeline (`similarity`)

Trigger points — public intake (`submit_triage_report`), manual creation
(`advisory_create`), GHSA import (`create_ghsa_linked_advisory`), and the
owner-only re-run button — all call
`similarity.services.request_check_safe`, which no-ops unless
`SIMILARITY_CHECK_ENABLED` ([INV-SIM-2](./invariant.md#inv-sim-2)) and never fails the parent
operation. `request_check` mirrors `publication.publish`: advisory row
lock, queued/running in-flight guard, a `SimilarityCheck` row pinned
(`PROTECT`) to the latest `AdvisoryVersion` ([INV-SIM-4](./invariant.md#inv-sim-4)), an audit
record, then `transaction.on_commit` → `safe_enqueue`.

The worker pipeline (`run_similarity_check`) spends at most **two** LLM
calls per check, independent of corpus size:

1. Empty pinned payload (no summary/details) → succeed with a note;
   zero LLM calls.
2. Postgres prefilter — same project only, all lifecycle states: exact
   alias / CVE / GHSA-id intersection and affected-package-name overlap
   are force-included, then trigram similarity over summary/details
   (the existing `pg_trgm` GIN indexes) fills up to
   `SIMILARITY_CANDIDATE_LIMIT` slots.
3. Fingerprint call — a compact normalized digest of the new report,
   cached in `AdvisoryFingerprint` keyed on a content hash of the
   duplicate-relevant payload subset; skipped while the hash is fresh.
4. Judge call — scores every candidate (cached fingerprints where
   fresh, truncated raw excerpts otherwise; candidate fingerprints are
   never generated inline). The reply is post-processed — hallucinated
   ids dropped, duplicates deduped, confidence clamped to 0–100,
   floored at `SIMILARITY_MIN_CONFIDENCE` — and the top 5 stored as
   ranked `SimilarityCandidate` rows.

Provider adapters (`similarity/llm/`) are raw-`requests` clients with no
SDK dependencies: the Anthropic Messages API, and OpenAI Chat
Completions covering both OpenAI and local OpenAI-compatible servers
(Ollama/vLLM/LM Studio — the on-prem option for embargoed content).
Failures are wrapped in `LlmError`, whose message passes through
`redact_secrets` ([INV-SIM-3](./invariant.md#inv-sim-3)). Results render in an owner-only sidebar
panel on the advisory detail page that polls over HTMX while a check is
queued/running ([INV-SIM-1](./invariant.md#inv-sim-1)); `manage.py backfill_fingerprints` warms
the fingerprint corpus for pre-existing advisories.

Checks orphaned in `queued`/`running` (worker hard-killed mid-run, or an
enqueue swallowed during a broker outage) are bounded by the
beat-scheduled `similarity-check-reaper` (§6.2, [INV-SIM-5](./invariant.md#inv-sim-5)) — after a
reap the panel's re-run button works again.

---

## 7. Configuration

### 7.1 Settings modules

`config.settings` is a Python package; `base.py` contains every
env-driven setting and the canonical defaults. The other modules
import via `from .base import *` and apply environment-specific
overrides:

| Module | Purpose |
|---|---|
| `base.py` | Authoritative env-var schema (via `django-environ`); INSTALLED_APPS; MIDDLEWARE; logging; security defaults; OIDC; Celery; publication repo defaults; GHSA + PMI; rate limits; Celery beat. |
| `dev.py` | DEBUG-on convenience for the docker-compose dev environment. |
| `prod.py` | Production hardening (no DEBUG, secure cookies enforced). |
| `test.py` | Points `DATABASE_URL` at the local Postgres (override host/port via `TEST_DATABASE_URL`); drops `mozilla_django_oidc` middleware; sets `CELERY_TASK_ALWAYS_EAGER=True`; sets `RATELIMIT_ENABLE=False`; sets `STEP_UP_REQUIRED=False`; uses `MD5PasswordHasher` for speed; in-memory email backend. |

### 7.2 Docker-compose dev environment

The dev environment is **docker-compose-driven** and self-contained.
The canonical configuration lives in `docker-compose.yml`'s
`x-django-env` anchor, which is reused by the `web` and `worker`
services. **`.env` files are not loaded by docker-compose** in dev
— `.env.example` is the reference document for production
operators, not a config source. The single file compose does load
is `dev/kanidm/.env.kanidm`, which carries the OIDC client secret
minted by `dev/kanidm/setup.sh` on first run.

First-time bring-up:

```sh
docker compose up -d kanidm
bash dev/kanidm/setup.sh
docker compose up
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_demo --with-publish-repo /tmp/advisoryhub-pub.git
```

Demo login: `alice@example.org` / `correcthorsebatterystaple`
(created by `dev/kanidm/setup.sh` to match `seed_demo`).

### 7.3 Environment variable inventory

Grouped by concern. See `config/settings/base.py` for defaults and
types.

**Django core.** `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`,
`DJANGO_SECRET_KEY`, `DJANGO_TIME_ZONE`, `DATABASE_URL`,
`CACHE_URL` (optional — falls back to LocMem), `LOG_FORMAT`
(`json`/`plain`), `LOG_LEVEL`, `CSRF_TRUSTED_ORIGINS`.

**Reverse proxy / edge TLS.** `USE_X_FORWARDED_PROTO` (default False —
trust the edge's `X-Forwarded-Proto` so `request.is_secure()` works
behind TLS termination) and `TRUSTED_PROXY_COUNT` (default 0 — number
of trusted reverse-proxy hops `common.net` strips from
`X-Forwarded-For` when resolving the client IP recorded in audit
entries).

**OIDC.** `OIDC_RP_CLIENT_ID`, `OIDC_RP_CLIENT_SECRET`,
`OIDC_OP_AUTHORIZATION_ENDPOINT`, `OIDC_OP_TOKEN_ENDPOINT`,
`OIDC_OP_USER_ENDPOINT`, `OIDC_OP_JWKS_ENDPOINT`,
`OIDC_OP_LOGOUT_ENDPOINT`, `OIDC_RP_SIGN_ALGO` (default `RS256`),
`OIDC_VERIFY_SSL` (default True), `OIDC_USE_PKCE` (default True),
`OIDC_GROUP_CLAIM` (default `groups`), `OIDC_ADMIN_GROUP` (default
`advisoryhub-security`), `OIDC_REQUIRE_EMAIL_VERIFIED` (default
False; INV-OIDC-6).

**Step-up.** `STEP_UP_REQUIRED` (default True),
`STEP_UP_MAX_AGE_SECONDS` (default 300).

**Celery / Valkey.** `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`,
`CELERY_TASK_ALWAYS_EAGER`. Prod: prefer `rediss://` (TLS) + AUTH; run Valkey
with `maxmemory-policy noeviction` (see §6.1).

**Security headers / CSP.** `CSP_REPORT_ONLY` (default False — the CSP is
enforced; set True to fall back to Report-Only while diagnosing a new violation)
and optional `CSP_REPORT_URI` (collector for the `report-uri` directive). The
nonce-based `script-src 'strict-dynamic'` policy (plus `style-src 'self'` with no
`'unsafe-inline'`, so no inline styles — htmx's indicator-`<style>` injection is
disabled via `htmx.config.includeIndicatorStyles = false`) and a fixed
`Permissions-Policy` are emitted by django-csp +
`common.middleware.PermissionsPolicyMiddleware` (not env-tunable).

**Readiness probes.** `READYZ_INCLUDE_PUB_REPO` (default False — `git ls-remote`
the pub repo) and `READYZ_INCLUDE_BROKER` (default False — probe the Celery broker)
add optional dependency checks to `/readyz`.

**Email.** `EMAIL_BACKEND` (default console),
`DEFAULT_FROM_EMAIL`, optional `ADVISORYHUB_BASE_URL` used to
construct absolute URLs in notification bodies; SMTP transport:
`EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`,
`EMAIL_HOST_PASSWORD` (secret), `EMAIL_USE_TLS`, `EMAIL_USE_SSL`.

**Footer help links.** `ADVISORYHUB_REPO_URL` (default
`https://github.com/mbarbero/advisoryhub`) is the base GitHub repo for
AdvisoryHub itself; the footer's "Report an issue" (`/issues/new`) and "Report a
vulnerability in AdvisoryHub" (`/security/advisories/new`, GitHub private
vulnerability reporting) links are derived from it, so a repo move is a single
env change. `ADVISORYHUB_DISCUSSIONS_URL` (default
`https://github.com/orgs/eclipse-csi/discussions`) backs the "Ask a question"
link. Blank disables the corresponding link. Resolved by
`common.context_processors.support_links`; the footer also shows the running app
version (`importlib.metadata.version("advisoryhub")` via
`common.context_processors.app_version`) but only to global admins — display-only
gating in `base.html`, [INV-AUTH-1](./invariant.md#inv-auth-1).

**Publication Git repo.** `PUB_REPO_URL`, `PUB_REPO_BRANCH`
(default `main`), `PUB_REPO_AUTH` (`ssh`|`token`),
`PUB_REPO_SSH_KEY_PATH`, `PUB_REPO_TOKEN`,
`PUB_COMMIT_AUTHOR_NAME`, `PUB_COMMIT_AUTHOR_EMAIL`,
`PUB_OSV_PATH_TEMPLATE` (default `osv/{year}/{advisory_id}.json`),
`PUB_CSAF_PATH_TEMPLATE` (default `csaf/{year}/{advisory_id}.json`)
— bucketed by the advisory's publication year (`{year}` = year of first
publication; the advisory id carries no year of its own). CVE Records:
`PUB_CVE_PATH_TEMPLATE` (default `cves/{year}/{bucket}/{cve_id}.json` —
cvelistV5 layout, `{year}`/`{bucket}` derived from the CVE id, e.g.
`CVE-2026-12345` → `2026/12xxx`), `PUB_CVE_ASSIGNER_ORG_ID` and
`PUB_CVE_ASSIGNER_SHORT_NAME` (default `eclipse`) — the CNA identity
stamped into generated CVE Records.

**Publication task reaper.** `PUB_TASK_STALE_RUNNING_AFTER_SECONDS`
(default 1800 — must comfortably exceed `run_publication`'s 660 s hard
`time_limit`) and `PUB_TASK_STALE_QUEUED_AFTER_SECONDS` (default 7200 —
must exceed the broker's 3600 s `visibility_timeout`): staleness
thresholds for the beat-scheduled reaper (§6.2, [INV-PUB-7](./invariant.md#inv-pub-7)).

**GHSA / GitHub App / PMI.** `GHSA_FEATURE_ENABLED` (default False),
`GHSA_AUTO_PUBLISH_ENABLED` (default True — auto-publish a GHSA-linked advisory
when GitHub publishes it, [INV-GHSA-3](./invariant.md#inv-ghsa-3)),
`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_PATH` (preferred in prod),
`GITHUB_APP_PRIVATE_KEY` (inline fallback for dev),
`GITHUB_APP_WEBHOOK_SECRET` (HMAC key — secret),
`GITHUB_APP_API_BASE_URL` (default `https://api.github.com`),
`GHSA_CVE_PUSH_STALE_RUNNING_AFTER_SECONDS` (default 1800) and
`GHSA_CVE_PUSH_STALE_QUEUED_AFTER_SECONDS` (default 7200 — must exceed
the 3600 s broker `visibility_timeout`): staleness thresholds for the
beat-scheduled CVE-push reaper (§6.2, [INV-GHSA-2](./invariant.md#inv-ghsa-2)), which runs even
while the GHSA feature is disabled (DB-only, no GitHub egress),
`GHSA_SYNC_INTERVAL_HOURS` (default 6 — cadence of the inbound-lifecycle
reconcile poll, §6.2 / [INV-GHSA-3](./invariant.md#inv-ghsa-3)),
`GHSA_DISCOVERY_INTERVAL_HOURS` (default 24 — cadence of the org-wide discovery
backstop sweep, §6.2 / [INV-GHSA-3](./invariant.md#inv-ghsa-3)),
`PMI_API_BASE_URL`, `PMI_API_TOKEN` (PMI is public; blank by
default), `PMI_SYNC_INTERVAL_HOURS` (default 6).

**Security-team roster sync (authenticated Eclipse API).**
`PMI_ROSTER_SYNC_ENABLED` (default False — gates the beat task and the
Admin Console button), `PMI_ROSTER_SYNC_INTERVAL_HOURS` (default 24),
`ECLIPSE_API_BASE_URL` (default `https://api.eclipse.org`),
`ECLIPSE_API_TOKEN_URL` (OAuth2 client-credentials token endpoint),
`ECLIPSE_API_CLIENT_ID` / `ECLIPSE_API_CLIENT_SECRET` (secret),
`ECLIPSE_API_SCOPE` (optional). The token and client secret are cached and
never logged; errors run through `redact_secrets` (INV-SECRET-*).

**Intake.** `ALTCHA_HMAC_KEY` (set to enable the self-hosted ALTCHA
proof-of-work captcha for anonymous reporters; empty = no captcha),
`RATELIMIT_INTAKE_ANON` (default `5/h`),
`RATELIMIT_INTAKE_USER` (default `20/h`),
`INTAKE_REPORT_RETENTION_DAYS` (default 365),
`INTAKE_DISABLED` (kill switch).

**Duplicate detection (similarity).** `SIMILARITY_CHECK_ENABLED`
(default False — the explicit consent gate for sending advisory content
to the LLM provider, [INV-SIM-2](./invariant.md#inv-sim-2)), `SIMILARITY_LLM_PROVIDER`
(`anthropic` | `openai`), `SIMILARITY_LLM_MODEL` (default
`claude-opus-4-8`), `SIMILARITY_LLM_API_KEY` (secret; blank for
keyless local servers), `SIMILARITY_LLM_BASE_URL` (empty = provider
default; set for OpenAI-compatible/local servers),
`SIMILARITY_LLM_TIMEOUT` (default 120 s read),
`SIMILARITY_CANDIDATE_LIMIT` (default 60),
`SIMILARITY_MIN_CONFIDENCE` (default 20),
`SIMILARITY_CHECK_STALE_RUNNING_AFTER_SECONDS` (default 1800 — must
comfortably exceed the 360 s hard `time_limit`) and
`SIMILARITY_CHECK_STALE_QUEUED_AFTER_SECONDS` (default 7200 — must
exceed the 3600 s broker `visibility_timeout`): staleness thresholds
for the beat-scheduled reaper (§6.2, [INV-SIM-5](./invariant.md#inv-sim-5)), which runs even while
the feature is disabled (DB-only, no LLM egress).

**Rate-limit master switch.** `RATELIMIT_ENABLE` (default True;
forced False in `test`).

**Access-log retention.** `AUDIT_ACCESS_LOG_RETENTION_ENABLED` (default
True), `AUDIT_ACCESS_LOG_RETENTION_DAYS` (default 90) — drive the
beat-scheduled `AccessLogEntry` partition maintenance (§6.2, §8.6,
[INV-AUDIT-5](./invariant.md#inv-audit-5)).

**Observability.** `SENTRY_DSN` (optional — enables Sentry via
`common.sentry.init_from_env`). `PROMETHEUS_WORKER_METRICS_PORT`
(default 0/disabled — the Celery worker's own metrics exporter port;
docker-compose sets 9808). `PROMETHEUS_MULTIPROC_DIR` (read straight
from the OS env by `django_prometheus`; set in prod to a writable
tmpfs so `/metrics` aggregates across gunicorn workers — see §8.8).

---

## 8. Operations

### 8.1 Health endpoints (`common.health`)

- `/healthz` — cheap liveness check; returns 200 unconditionally
  when the process can answer. Suitable for k8s liveness probes.
- `/readyz` — readiness check; pings the database, the cache, and
  (when `PUB_REPO_URL` is set and `READYZ_INCLUDE_PUB_REPO=True`)
  the publication remote via `git ls-remote --exit-code --heads`.
  Returns 200 only if every check passes; otherwise 503 with a
  JSON body `{"status": "fail", "failures": {<name>: <ExcType>}}`.
  Each check is wrapped so a failure logs the full trace
  server-side but the client gets only a short type name.

### 8.2 Logging (`common.logging` + `common.middleware`)

- `RequestIDMiddleware` (first non-Prometheus middleware) generates
  or honours an incoming `X-Request-ID` header and binds it to a
  thread-local for the request lifetime.
- `RequestIDFilter` is registered as a logging filter so every log
  record carries `record.request_id`.
- Two formatters are configured: `json` (single-line JSON to
  stderr, suitable for log shippers) and `plain` (human-readable).
  `LOG_FORMAT` selects between them; `LOG_LEVEL` sets the root
  level.
- `django.request` and `django.server` are pinned to `WARNING` and
  `propagate=False` so Django's per-request access lines do not
  drown out application logs.

### 8.3 Metrics

`django_prometheus` is installed; `PrometheusBeforeMiddleware` is
first and `PrometheusAfterMiddleware` is last in `MIDDLEWARE`, so
the in-flight timer covers the entire request lifecycle. The
`/metrics` endpoint is wired **unconditionally** (`config/urls.py`,
via the `django_prometheus.urls` include); it carries no auth and
must be kept off the public ingress (private port / network policy /
reverse-proxy auth header).

On top of django-prometheus's defaults (request counts, response
status, the request-latency histogram, DB and cache series) the app
exports custom business series defined in `common.metrics`:

- `advisoryhub_publication_total{status}` — publication runs by
  status (`started`/`succeeded`/`failed`), with
  `advisoryhub_publication_stage_total{stage}` and the
  `advisoryhub_publication_duration_seconds` histogram (instrumented
  in `publication/services.py` + `publication/tasks.py`).
- `advisoryhub_celery_task_total{task,status}` and
  `advisoryhub_celery_task_duration_seconds{task}` — set from Celery
  signal handlers in `common.celery_metrics`.
- `advisoryhub_backlog{queue}` — operator queue depths, refreshed
  every 60s by the `audit.tasks.refresh_backlog_gauges` beat task
  (queries mirror the Admin Console inbox strip). The `pub_failed`
  series stays per-source (failed `PublicationTask`s only) for
  dashboard continuity; the inbox's "publish required" chip combines
  it with republish-required advisories, so the chip count can exceed
  the `pub_failed` gauge.

These custom series are produced in the **worker** process, which
serves no HTTP, so the worker runs its own exporter
(`prometheus_client.start_http_server` on
`PROMETHEUS_WORKER_METRICS_PORT`, default 0/disabled) as a *second*
scrape target. The worker uses the **threads** pool
(`--pool=threads`): all tasks run in one process, so the single
exporter (started on `worker_ready`) sees every worker thread's
counts and `--concurrency` can be raised freely. The default
**prefork** pool would fork separate-memory child processes whose
counts a MainProcess exporter can't see — switching to it requires
`prometheus_client` multiprocess mode (a per-container
`PROMETHEUS_MULTIPROC_DIR`), the same mechanism as the gunicorn web
path (§8.8). The `advisoryhub_backlog` gauge uses
`multiprocess_mode="mostrecent"` so it reports correctly under
gunicorn multiprocess too.

### 8.4 Sentry

`common.sentry.init_from_env()` is called at the bottom of
`base.py`. It initialises Sentry only when `SENTRY_DSN` is set and
is otherwise a no-op.

### 8.5 Rate limits (`common.ratelimit`)

`django-ratelimit` is the underlying engine. Two helpers wrap it:

- `html_ratelimit(*, rate, key=per_user_or_ip)` — for HTML / HTMX
  views; returns a 429 with a short human message on hit.
- `json_ratelimit(*, rate, key=per_user_or_ip)` — for the JSON API;
  returns
  `{"error": "rate_limited", "message": ..., "retry_after": ...}`.

`per_user_or_ip` keys on the authenticated user when present and
falls back to the source IP (honouring `X-Forwarded-For` for proxied
deployments). Public intake uses two separate rate strings —
`RATELIMIT_INTAKE_ANON` (per IP) and `RATELIMIT_INTAKE_USER` (per
user) — picked dynamically in `intake.views`.

### 8.6 Audit hygiene

The audit log is split into two tables (see [INV-AUDIT-5](./invariant.md#inv-audit-5)). The durable,
append-only **ledger** `AuditLogEntry` holds governance/timeline events. The
high-volume, retention-managed **access log** `AccessLogEntry` holds the actions
in `audit.models.EPHEMERAL_ACTIONS` (advisory views, GHSA/PMI chatter,
authentication events — login/logout/failed-login/step-up — and per-recipient
notification deliveries); `audit.services.record()` routes by action. The access log is monthly
range-partitioned on `created_at`, so retention is a `DROP PARTITION` (O(1), no
per-row DELETE) rather than a sweep — handled by the daily
`maintain_access_log_partitions` task (§6.2) and the matching command.

**First-view compliance receipt** ([INV-AUDIT-6](./invariant.md#inv-audit-6)).
`advisory.viewed` is ephemeral (every open, pruned at 90 days), but the *first*
open of an advisory by a given user also emits a durable `advisory.first_seen`
`AuditLogEntry` — an implicit "acknowledgment of receipt" proving the user was
made aware, retained indefinitely on the ledger. `advisories.views.advisory_detail` reuses the
`AdvisoryVisit.update_or_create` `created` flag as the once-per-(user, advisory)
signal and writes the receipt via `audit.services.record` **without** IP/UA, so
the never-pruned row carries no PII beyond the actor FK (erasure-clean — see
`forget_user` below). `advisory.first_seen` stays out of `EPHEMERAL_ACTIONS` and
out of the timeline tiers (admin-queryable, not per-event timeline noise).

**Companion suppression on the timeline.** Two structured ledger actions are
likewise durable but kept off the activity timeline because a descriptive
companion already narrates the same change: `advisory.review_status_changed`
(`REVIEW_TASK_STATUS_CHANGED`) is always paired with an `ADVISORY_REVIEW_*` row,
and `advisory.state_changed` is paired with `ADVISORY_DISMISSED` /
`ADVISORY_TRIAGE_PROMOTED` (the redundant write is tagged `metadata.narrated=true`
and dropped at the DB layer in `advisories.timeline.events_for_advisory`). State
changes that are the sole narration of their event — reopen, the GHSA
accepted-to-draft flip, and the `reopen_review` `review_status` flip — are left
untagged and stay. See advisory-lifecycle.md §3.1.

Management commands in `audit/management/commands/`:

- `prune_audit` — deletes **ledger** rows older than a configurable
  retention horizon, using the trigger bypass. Production retention is
  conservative and the command is intended for explicit operator invocation,
  not automated cron. Now rarely needed: the high-volume events live in the
  access log, which prunes itself by partition drop. Each non-dry-run
  invocation records an `AUDIT_PRUNED` entry on the ledger itself (horizon,
  exact cutoff, deleted row count, optional operator reason), so the act of
  pruning is part of the immutable history. The *retention floor* — the most
  aggressive cutoff ever recorded across surviving `AUDIT_PRUNED` entries
  (`audit.services.pruned_history_floor`) — is surfaced to readers: a marker at
  the oldest end of any affected advisory's activity timeline (an advisory whose
  `created_at` predates the floor) and a footer note on the Admin Console's
  Audit-logs page, so a pruned history reads as deliberately truncated rather
  than simply short.
- `maintain_access_log_partitions` — manual equivalent of the beat task:
  create the upcoming `AccessLogEntry` partition, drop months past the horizon
  (`--dry-run` reports what would drop).
- `forget_user` — scrubs identifying fields on `AuditLogEntry`,
  `AdvisoryIntakeMetadata`, and other PII-bearing rows for a
  named user, and **deletes** the user's `AccessLogEntry` rows outright (the
  access log is retention-bounded, not a compliance ledger). Advisories and
  other governance objects survive; only the identifying columns are nullified
  or cleared.

### 8.7 Seed / demo data

`python manage.py seed_demo --with-publish-repo /tmp/pub.git`
populates the dev environment with projects, users, advisories in
each lifecycle state, sample comments, and an initialised bare Git
publication repository. The command uses the dev-only
`_unsafe_dev_reset_bypass()` context manager when invoked with
`--reset`.

### 8.8 Metrics scraping & alerting

A dev/demo Prometheus + Grafana stack lives under `dev/observability/`
and is gated behind the `observability` docker-compose profile, so it
is opt-in (`docker compose --profile observability up prometheus
grafana`, or `mise run obs-up`). It is **not** for production — prod is
scraped by the operator's own Prometheus.

- **Scrape targets** (`dev/observability/prometheus.yml`): the web
  `/metrics` (django-prometheus series), the worker exporter
  `worker:9808` (the `advisoryhub_*` series), and Prometheus itself.
- **Alert rules** (`dev/observability/rules/advisoryhub.rules.yml`),
  in three groups: *availability* (target down, 5xx ratio, p95 latency
  burn), *pipeline* (publication failure rate, stuck failed-publication
  backlog, Celery failure spike), and *readiness* (work queued but no
  Celery progress — the visible proxy for a down broker, since
  `safe_enqueue` swallows broker outages; cf. `READYZ_INCLUDE_BROKER`).
- **Grafana** auto-provisions the Prometheus datasource and two
  dashboards (request rate/errors/latency; publication outcomes &
  duration, Celery throughput, backlog).

**Proposed SLOs** (defaults — tune to operations):

| SLO                          | Target  | Window      | Backing alert                       |
| ---------------------------- | ------- | ----------- | ----------------------------------- |
| Web availability (non-5xx)   | ≥ 99.5% | 30d         | `AdvisoryHubHigh5xxRate`            |
| p95 request latency          | < 1s    | 5m rolling  | `AdvisoryHubLatencySLOBurn`        |
| Publication success          | ≥ 90%   | 24h         | `AdvisoryHubPublicationFailureRate` |
| Scrape targets reachable     | 99.9%   | 30d         | `AdvisoryHubTargetDown`            |

**Production note.** `/metrics` must stay on a private port. Under
multiple gunicorn workers the custom counters only aggregate when
`prometheus_client` multiprocess mode is on: set
`PROMETHEUS_MULTIPROC_DIR` to a writable, empty-at-boot tmpfs and run
`gunicorn config.wsgi -c gunicorn.conf.py` (its `child_exit` hook reaps
dead workers' mmap files). The Celery worker exports its own series on
`PROMETHEUS_WORKER_METRICS_PORT`; scrape both targets.

### 8.9 Admin Stats page (operator SLAs)

Distinct from the Prometheus series (§8.3), the Admin Console **Stats**
page (`/admin/stats/`, admin-only via `can_review`) reports two
human-facing SLAs computed on demand from the database by
`admin_console/stats.py`:

- **Time to first response (TTFR)** — intake/triage-sourced advisories
  only: `AdvisoryIntakeMetadata.submitted_at` → the *earliest*
  `AuditLogEntry` in `FIRST_RESPONSE_ACTIONS`
  (`advisory.triage_promoted`, `advisory.dismissed`,
  `advisory.flagged_for_routing`). `FIRST_RESPONSE_ACTIONS` is the
  single authoritative definition (see advisory-lifecycle §10).
- **Time to publish (TTP)** — `Advisory.created_at` →
  `Advisory.published_at`.

Each is reported as mean + **p95** (the single SLA percentile — p95 is the
industry standard and matches the sparkline; p90/p99 were dropped as noise
at this small per-period sample size) over **trailing windows** (last week,
month, 3/6/12 months, all time) plus an optional custom range **and a
per-project filter** (`?project=<slug>`, scoping tables + sparklines + the
reverted tally to one project), with a **period-over-period** trend chip vs
the immediately-preceding equal-length window (lower is better). Samples are
**completion-anchored** (bucketed by the window their end event lands in) so
a window reports the work that *completed* in it. A separate **reverted**
tally counts intake reports promoted to draft and later dismissed (anchored
on the dismissal); such reports still contribute a TTFR sample anchored on
the promotion.
Percentiles are computed in Python (linear interpolation) — the data is
low-volume and this keeps the engine unit-testable without a DB
(`admin_console/test_stats.py`). TTFR is bounded by the audit-retention
window (old first-response rows may be pruned); TTP reads only `Advisory`
columns and is immune. The demo seed (`seed_demo._seed_stats_demo`)
backdates published + intake advisories across every window so the page is
demonstrable.

Each metric section also carries a compact **trend sparkline** — a
server-rendered inline `<svg>` line of mean + p95 over the last 12 months in
twelve 30-day buckets (`bucket_series` + `build_sparkline`), with value
(max / mid / 0) and month axes and a "now: mean … · p95 …" current-value
readout. It is CSP-clean: the SVG holds only data geometry (attributes), the
axis labels are HTML and the gridlines are CSS, all colour in
`static/advisoryhub.css` classes (no JS, no chart library), mirroring the
existing inline-SVG icon set.

---

## 9. Testing strategy

### 9.1 Database

Tests run against PostgreSQL — the same engine as prod, dev, and demo —
so the append-only audit triggers, the advisory non-deletion trigger,
the `pg_trgm` indexes, and the JSONB query paths are all exercised.
`config.settings.test` defaults `DATABASE_URL` to the local compose
Postgres; set `TEST_DATABASE_URL` to target a different host/port (CI
points it at its service container). Start Postgres before running the
suite (`docker compose up -d postgres` or `mise run up`). `--reuse-db`
(in pytest `addopts`) keeps the test database between runs; pass
`--create-db` after changing a migration.

```sh
docker compose up -d postgres
DJANGO_SETTINGS_MODULE=config.settings.test pytest
```

### 9.2 Test settings overrides

`config.settings.test` removes complications that hurt unit-test
ergonomics:

- **OIDC middleware stripped.** `mozilla_django_oidc.middleware.SessionRefresh`
  is filtered out of `MIDDLEWARE`. Tests use `client.force_login`
  to set the session; without the strip, every request would
  redirect to the IdP.
- **`CELERY_TASK_ALWAYS_EAGER=True`.** Celery `.delay()` runs
  synchronously in-process; combined with
  `CELERY_TASK_EAGER_PROPAGATES=True` (from `base.py`), failures
  in tasks raise into the test.
- **`RATELIMIT_ENABLE=False`.** No per-IP / per-user throttling
  for the duration of tests. The dedicated rate-limit tests
  re-enable it via `@override_settings(RATELIMIT_ENABLE=True)`
  (and adjust the rate strings as needed).
- **`STEP_UP_REQUIRED=False`.** Publish actions don't need a
  step-up re-auth; the dedicated step-up tests re-enable it via
  `@override_settings(STEP_UP_REQUIRED=True)`.
- **`MD5PasswordHasher`.** Faster than PBKDF2 for the rare test
  that creates a real password.
- **`locmem` email backend.** `django.core.mail.outbox` captures
  notifications for assertion.
- **Insecure cookies.** `SESSION_COOKIE_SECURE=False`,
  `CSRF_COOKIE_SECURE=False` so the test client (no TLS) can
  exercise them.

### 9.3 Test layout

Tests live next to the code they exercise: each app has either a
`tests.py` (small suites) or a `tests/` package (large suites).
Pytest is the runner; the project ships a top-level `conftest.py`
that wires up the Django test plumbing.

Tested concerns include but are not limited to:

- Authorisation predicates for every state and role combination.
- Append-only guards (model layer for all three append-only
  tables, plus the Postgres triggers under the Postgres CI run).
- Triage flow (submit, promote, dismiss, reassign, flag, unflag).
- Comment threading, mentions, comment visibility (internal vs. everyone with access).
- Notification recipient resolution across grant changes and
  per-advisory overrides.
- Publication pipeline including push success, push failure
  branches, retry, OSV/CSAF schema validation, and the redacted
  `last_error` shape.
- OIDC group sync (`sync_groups_from_claims`) and step-up
  freshness.
- Rate limits (per-IP intake anonymous and per-user intake
  authenticated).
- GHSA discovery, per-advisory sync, refresh-for-publish, EF-CVE
  push, webhook HMAC verification, installation lifecycle.

### 9.4 No external dependencies

Tests do not require a real OIDC provider, real email delivery, or
a real Git remote:

- OIDC is bypassed via `force_login` thanks to the middleware
  strip.
- Email lands in `mail.outbox` via the locmem backend.
- Publication tests use a **local bare repository** created in a
  `tempfile.TemporaryDirectory()`; the `PUB_REPO_URL` setting
  is pointed at the bare repo's path so the real `git` subprocess
  calls exercise the actual flow. Tests skip themselves when
  `git` is not on `PATH`.

### 9.5 Lint & format

`ruff check .` and `ruff format --check .` run as part of CI.
Configuration is in `pyproject.toml` (`E,F,W,I,B,UP,DJ`; line
length 100; `E501` ignored). Migrations and tests have relaxed
rules; `advisories/models.py` ignores `DJ012` (intentional `Meta`
override in `AdvisoryQuerySet`).

CI also runs `python manage.py makemigrations --check --dry-run`
and `python manage.py check --deploy --fail-level WARNING`.

---

## 10. Cross-reference index

- [`invariant.md`](./invariant.md) — load-bearing rules with stable
  `INV-XYZ-N` IDs, the deep-dive for the rules referenced above.
- [`advisory-lifecycle.md`](./advisory-lifecycle.md) — state
  diagrams, transition tables, the publication sequence diagram.
- [`permissions.md`](./permissions.md) — actors, roles, capability
  matrix, full enforcement surface table (web / API / admin /
  Celery / intake / comment-read filter).
- [`requirements.md`](./requirements.md) — top-down functional
  specification (actors, domain concepts, use cases).
- [`../../CLAUDE.md`](https://github.com/mbarbero/advisoryhub/blob/main/CLAUDE.md) — agent-facing operational
  notes (app layout, common commands, network policy, persistence
  rules).
- [`../../README.md`](https://github.com/mbarbero/advisoryhub/blob/main/README.md) — setup instructions.
