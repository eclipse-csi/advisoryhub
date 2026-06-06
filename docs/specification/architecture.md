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
| Markdown | `markdown-it-py` + `bleach` | Strict allowlist; rendered HTML never stored. |
| Git client | `GitPython` | Used by the publication pipeline. |
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
| `advisories` | `Advisory`, `AdvisoryVersion`, `AdvisoryIntakeMetadata`, validators, identifiers, permissions, services (triage flow + the version-append helper), edit views, triage views. |
| `access` | `AdvisoryAccessGrant`, `PendingInvitation`, grant / revoke / invite / redeem services, HTMX views. |
| `comments` | `AdvisoryComment`, `CommentVersion`, markdown rendering + sanitisation, mention extraction, list view. |
| `notifications` | Global preference + per-advisory override models, recipient resolver (`filter_for_event`), Celery email tasks (advisory events, triage events, comments, invitations). |
| `workflows` | `CveRequestTask`, `ReviewTask`, `OrphanCve`, and the services that drive their state machines. |
| `publication` | `PublicationTask`, `PublicationArtifact`, `PublicationRepositoryConfig`, OSV + CSAF builders + vendored schemas, the Git service, the Celery worker. |
| `admin_console` | The /admin/ sidebar shell and its section views (Inbox, CVEs, Publications, Audit, Projects). |
| `api` | JSON API surface re-using the same `can_*` predicates as the web views. |
| `ghsa` | GitHub App client + JWT handling, PMI mirror, GHSA discovery / per-advisory sync, EF-CVE push, webhook ingest. |
| `intake` | The public report form (`/report/`), `HoneypotSubmission`, rate-limited project picker JSON. |

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
  is reachable from the dashboard as "Re-publish".

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
prod), `OIDC_GROUP_CLAIM`, `OIDC_ADMIN_GROUP`. RP-initiated logout
uses `accounts.auth.provider_logout`; `OIDC_STORE_ID_TOKEN=True` so
the logout request can include `id_token_hint`.

### 3.7 Step-up authentication

`accounts.step_up` implements a session-scoped freshness check
(`request.session["step_up_auth_at"]` within
`STEP_UP_MAX_AGE_SECONDS`, default 300 s). The publish view and the
GitHub App configuration view call
`require_step_up_or_redirect(request, next_url=…)`; if the timestamp
is missing or stale, the user is bounced through a
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
   `PUBLICATION_CSAF_GENERATED`).
   Validation is schema-based against the JSON Schemas vendored in
   `publication/schemas/` ([INV-PUB-6](./invariant.md#inv-pub-6)).
5. Persist `PublicationArtifact` rows for each kind via
   `update_or_create` keyed on `(task, kind)`, carrying the
   serialised path and the validated JSON content. This is the
   source of truth for the admin-console preview screens.
6. Hand the two serialised documents to
   `publication.git_service.publish_files`.

### 4.3 Git layer (`publication.git_service.publish_files`)

For each call:

1. `_ssh_env(config)` context manager: if auth mode is `ssh`,
   sets `GIT_SSH_COMMAND` to
   `ssh -i <key> -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o BatchMode=yes`
   for the duration of the clone and restores the previous value on
   exit ([INV-SECRET-2](./invariant.md#inv-secret-2)).
2. A fresh `tempfile.TemporaryDirectory(prefix="advisoryhub-pub-")`
   ([INV-PUB-1](./invariant.md#inv-pub-1)).
3. `_embed_token(config)`: if auth mode is `token` and the URL is
   HTTPS, rewrites it to
   `https://x-access-token:$PUB_REPO_TOKEN@…`. The rewritten URL is
   only used as the `Repo.clone_from` argument; it is never
   persisted, logged, or audited.
4. `Repo.clone_from(effective_url, workdir, branch=config.branch,
   depth=1)` — shallow clone
   ([INV-PUB-3](./invariant.md#inv-pub-3)).
5. `_configure_author` sets `user.name` and `user.email` from the
   config, and forces `commit.gpgsign=false` /
   `tag.gpgsign=false` so a host-wide signing config can never
   block the bot.
6. `_write_files(workdir, files)` writes each `WrittenFile` and
   returns whether anything changed. Idempotent on content: if both
   the OSV and the CSAF are byte-identical to what is already on
   the branch, no commit is created and the function returns
   `PublishResult(commit_sha=HEAD, …)`.
7. Otherwise the index is staged, a commit is created with the
   configured author + the deterministic message
   `Publish advisory <advisory_id>`, and `origin.push` is run
   against `refspec=f"HEAD:{config.branch}"`. `_check_push`
   inspects each `PushInfo` and raises `GitPublicationError` on
   any error / rejected / remote-rejected flag.
8. All raised error strings flow through `_redact(str, config)`
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
sync emits a `PMI_PROJECT_REPOS_SYNCED` audit row.

### 5.3 GHSA discovery & per-advisory sync

GHSA discovery happens on demand — `ghsa.services.sync_ghsas_for_project`
for one project or `sync_ghsas_for_all_projects` for the whole org;
the admin console exposes both. Discovery walks each `(owner, name)`
in the project's repo mirror, lists GHSAs, and creates or updates
`Advisory(kind=ghsa_linked)` rows whose `ghsa_id` is uniquely
mapped ([INV-ID-2](./invariant.md#inv-id-2)). A run is recorded as
a `GhsaSyncRun` with counts and last error.

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

### 5.5 Webhook ingest

Inbound webhook deliveries are HMAC-verified against
`GITHUB_APP_WEBHOOK_SECRET` and deduplicated by delivery id via
the `WebhookDelivery` table. Recognised events route to handlers in
`ghsa.webhooks`; unrecognised events are logged as
`GHSA_WEBHOOK_REJECTED` and dropped. Installation lifecycle events
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

### 5.7 Feature gate

The integration is fronted by the `GHSA_FEATURE_ENABLED` boolean
flag. With the flag off, GHSA views and tasks short-circuit; the
admin console hides the GHSA sections.

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
| `CELERY_BROKER_TRANSPORT_OPTIONS` | `{"visibility_timeout": 3600}` | Redelivery window for the Redis/Valkey transport; must exceed the longest task. |
| `run_publication` task | `acks_late`, `reject_on_worker_lost`, `soft_time_limit=600`, `time_limit=660` | At-least-once for the durable publication task; a hung git push fails-and-is-retryable rather than running until the visibility window. |

Run a worker with `celery -A config worker -l info`. Run beat with
`celery -A config beat`.

**Ops:** the broker (db0), result backend (db1) and cache (db2) share one Valkey
instance. Run it with `--maxmemory-policy noeviction` (the default) so an eviction
can never silently drop broker messages or rate-limit/maintenance keys, and in prod
use `rediss://` (TLS) + AUTH. `/readyz` can probe the broker when
`READYZ_INCLUDE_BROKER=True` (off by default — see §7.3).

### 6.2 Beat schedule

Three periodic jobs are registered in `config/settings/base.py`:

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
    "security-roster-sync": {
        "task": "projects.tasks.run_roster_sync",
        "schedule": timedelta(hours=PMI_ROSTER_SYNC_INTERVAL_HOURS),
    },
}
```

`access-log-partition-maintenance` creates the upcoming month's
`AccessLogEntry` partition and drops months older than
`AUDIT_ACCESS_LOG_RETENTION_DAYS` (default 90); it no-ops when
`AUDIT_ACCESS_LOG_RETENTION_ENABLED` is False (see §8.6, INV-AUDIT-5).

`security-roster-sync` mirrors each project's Eclipse security team into
`SecurityTeamRosterEntry` rows and pre-provisions notification-only shadow
users (`User.is_provisioned=True`) so `@team` mentions and team notifications
reach members who have never logged in. It uses the **authenticated** Eclipse
API (`projects/eclipse_api.py`, OAuth2 client-credentials) to resolve member
emails the public PMI feed hides, and **no-ops unless `PMI_ROSTER_SYNC_ENABLED`
is set** (default off). Shadow users hold no authorization (INV-OIDC-5); reach
is notification-only (INV-ROSTER-1).

GHSA *discovery* is intentionally not on beat — it is
user-triggered, scoped (project or all), and recorded as a
`GhsaSyncRun`.

### 6.3 Task inventory

| App | Task | Purpose |
|---|---|---|
| `publication` | `run_publication` | Build → validate → push → flip state. |
| `notifications` | `send_advisory_event_email` | Lifecycle events (created, submitted for review, published, publication export status). |
| `notifications` | `send_comment_email` | Comment + mention notifications. |
| `notifications` | `send_advisory_triage_event_email` | Triage-flow events to the project security team or admins. |
| `notifications` | `send_intake_event_email` | Legacy no-op to drain queues from before the triage refactor. |
| `notifications` | `send_invitation_email` | Invitation delivery. |
| `ghsa` | `run_pmi_repo_sync` | Beat-scheduled PMI mirror refresh. |
| `ghsa` | `run_ghsa_sync_project` | On-demand GHSA discovery for one project. |
| `ghsa` | `run_ghsa_sync_all` | On-demand GHSA discovery for the whole org. |
| `ghsa` | `run_cve_push` | Push EF-assigned CVE to a linked GHSA. |
| `audit` | `maintain_access_log_partitions` | Beat-scheduled `AccessLogEntry` partition create-ahead + drop-expired. |
| `projects` | `run_roster_sync` | Beat-scheduled security-team roster sync (shadow-user provisioning); no-op unless `PMI_ROSTER_SYNC_ENABLED`. |

Idempotency story:

- `run_publication` is short-circuited when the task is no longer
  in a queueable state; success / failure is terminal per-row, and
  the file write is idempotent on content.
- GHSA per-advisory sync writes a new version only on payload
  change.
- Notification tasks recompute recipients at send time, so an
  enqueued-then-revoked grant produces no email.

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
(`json`/`plain`), `LOG_LEVEL`.

**OIDC.** `OIDC_RP_CLIENT_ID`, `OIDC_RP_CLIENT_SECRET`,
`OIDC_OP_AUTHORIZATION_ENDPOINT`, `OIDC_OP_TOKEN_ENDPOINT`,
`OIDC_OP_USER_ENDPOINT`, `OIDC_OP_JWKS_ENDPOINT`,
`OIDC_OP_LOGOUT_ENDPOINT`, `OIDC_RP_SIGN_ALGO` (default `RS256`),
`OIDC_VERIFY_SSL` (default True), `OIDC_USE_PKCE` (default True),
`OIDC_GROUP_CLAIM` (default `groups`), `OIDC_ADMIN_GROUP` (default
`advisoryhub-security`).

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
construct absolute URLs in notification bodies.

**Publication Git repo.** `PUB_REPO_URL`, `PUB_REPO_BRANCH`
(default `main`), `PUB_REPO_AUTH` (`ssh`|`token`),
`PUB_REPO_SSH_KEY_PATH`, `PUB_REPO_TOKEN`,
`PUB_COMMIT_AUTHOR_NAME`, `PUB_COMMIT_AUTHOR_EMAIL`,
`PUB_OSV_PATH_TEMPLATE` (default `osv/{year}/{advisory_id}.json`),
`PUB_CSAF_PATH_TEMPLATE` (default `csaf/{year}/{advisory_id}.json`)
— bucketed by the advisory's publication year (`{year}` = year of first
publication; the advisory id carries no year of its own).

**GHSA / GitHub App / PMI.** `GHSA_FEATURE_ENABLED` (default False),
`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_PATH` (preferred in prod),
`GITHUB_APP_PRIVATE_KEY` (inline fallback for dev),
`GITHUB_APP_WEBHOOK_SECRET` (HMAC key — secret),
`GITHUB_APP_API_BASE_URL` (default `https://api.github.com`),
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

**Intake.** `HCAPTCHA_SITE_KEY`, `HCAPTCHA_SECRET_KEY` (both must
be set for hCaptcha to engage — otherwise silently bypassed),
`RATELIMIT_INTAKE_ANON` (default `5/h`),
`RATELIMIT_INTAKE_USER` (default `20/h`),
`INTAKE_REPORT_RETENTION_DAYS` (default 365),
`INTAKE_DISABLED` (kill switch).

**Rate-limit master switch.** `RATELIMIT_ENABLE` (default True;
forced False in `test`).

**Health.** `READYZ_INCLUDE_PUB_REPO` (default False — opt-in
because it is a network round-trip).

**Observability.** `SENTRY_DSN` (optional — enables Sentry via
`common.sentry.init_from_env`).

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
default metrics endpoint can be enabled by adding the
`django_prometheus.urls` include if metrics are scraped.

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

The audit log is split into two tables (see INV-AUDIT-5). The durable,
append-only **ledger** `AuditLogEntry` holds governance/timeline events. The
high-volume, retention-managed **access log** `AccessLogEntry` holds the actions
in `audit.models.EPHEMERAL_ACTIONS` (advisory views, GHSA/PMI chatter,
authentication events — login/logout/failed-login/step-up — and per-recipient
notification deliveries); `audit.services.record()` routes by action. The access log is monthly
range-partitioned on `created_at`, so retention is a `DROP PARTITION` (O(1), no
per-row DELETE) rather than a sweep — handled by the daily
`maintain_access_log_partitions` task (§6.2) and the matching command.

Management commands in `audit/management/commands/`:

- `prune_audit` — deletes **ledger** rows older than a configurable
  retention horizon, using the trigger bypass. Production retention is
  conservative and the command is intended for explicit operator invocation,
  not automated cron. Now rarely needed: the high-volume events live in the
  access log, which prunes itself by partition drop.
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
- Comment threading, mentions, internal-vs-public visibility.
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
  is pointed at the bare repo's path so the real `GitPython`
  call exercises the actual flow. Tests skip themselves when
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
- [`../../CLAUDE.md`](../../CLAUDE.md) — agent-facing operational
  notes (app layout, common commands, network policy, persistence
  rules).
- [`../../README.md`](../../README.md) — setup instructions.
