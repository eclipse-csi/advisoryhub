---
name: adversarial-review
description: Review the changes of an AdvisoryHub branch adversarially before a pull request is opened. Try to disprove the assumptions of the change against the invariants and the permission model, verify each finding on the state reviewed, and give a verdict (ready, blocked or inconclusive). Read-only by default; confirmed bugs are fixed only when the user asks for a fix pass. Use it before opening or preparing a pull request, and when asked for a self-review, a pre-PR review or a critical review of the current changes. Nothing is posted to GitHub.
---

# Adversarial review before a pull request

The conventions, commands and commit policy are in `CLAUDE.md`. The rules the change is judged against are the
specification set in `docs/specification/` (authoritative), above all `invariant.md` and `permissions.md`, and the
constitution in `.specify/memory/constitution.md`. This review posts nothing to GitHub and does not replace the review
of a maintainer, nor the Spec Kit reviews the constitution makes mandatory (Principles VIII and IX): those check the
change against the rules, this one tries to break it. It ends with a verdict, and a pull request is not opened while
the verdict is `blocked`.

## Ground rules

- **Try to disprove the assumptions of the change.** For everything the change takes for granted (the caller is
  authorized, the advisory is in a given state, the request comes from the UI, a Celery task runs once and in order,
  the push succeeds, an external API answers completely, the input is well formed, a feature flag is on), look for the
  role, the state, the input or the sequence of requests where it does not hold. Zero findings is a valid outcome: do
  not manufacture any.
- **Read-only by default.** The review changes no file of the checkout. Fix the confirmed bugs only when the user asks
  for a fix pass (step 5). A `blocked` verdict stands even if the review changed nothing.
- **Checks that do not fix.** `prek` rewrites files (`ruff check --fix`, `ruff format`, the whitespace, end-of-file and
  line-ending fixers). During the review, run it in a separate temporary worktree checked out at `HEAD`, not in the
  one of question 11, which holds `<base>`. The hooks call `uv run --no-sync --python .venv`, a path relative to the
  worktree, which has no virtual environment: link the one of the checkout first,
  `ln -s <checkout>/.venv <tmp-dir>/.venv && cd <tmp-dir> && prek run --files <files>`, and add
  `--hook-stage pre-push` for mypy, the Django checks and pip-audit (which needs the network); remove it afterwards
  with `git worktree remove --force <tmp-dir>`. A worktree at `HEAD`
  leaves out uncommitted changes: check those with the non-fixing commands on the checkout, `uv run ruff check --no-fix
  <files>`, `uv run ruff format --check <files>`, `DJANGO_SETTINGS_MODULE=config.settings.test uv run mypy`,
  `DJANGO_SETTINGS_MODULE=config.settings.test uv run python manage.py makemigrations --check --dry-run`,
  `bash dev/check_vendored_assets.sh`, `python3 dev/check_template_comments.py`, `python3 dev/check_import_direction.py`,
  and `uv run pytest`. If a check rewrote a file anyway, report it rather than keep the change.
- **Review with fresh eyes.** If your tool can run a separate agent or session, give it the diff, the goal of the
  change and this skill, but not your own analysis, so that it does not inherit your assumptions. Otherwise, re-read
  the diff from the start, file by file, as if someone else had written it.
- **No finding without evidence.** Keep a finding only with a concrete failure scenario (actor, role and advisory
  state, or input, then wrong result) checked on the state you reviewed (step 1), or better, reproduced by a test.
  When the finding breaks an invariant, name its `INV-*` ID and its tier: a Critical one is a release blocker.
- **Never touch a real external system.** No push to a real publication repository, and no call to GitHub, the PMI
  API, an LLM provider, an OIDC provider or a mail server. Scenarios run on the test setup: the local bare repository
  of `publication/tests/test_pipeline.py`, `CELERY_TASK_ALWAYS_EAGER`, the locmem mail backend, mocked HTTP. Leave the
  user's dev stack and its database as they are: no `docker compose down -v`, `migrate`, `seed_demo` or `forget_user`
  on them.

## 1. Define the state under review

`<base>` is the branch the pull request will target, usually `main` of `eclipse-csi/advisoryhub`, kept up to date.

```shell
git status --short                         # staged, unstaged and untracked files
git diff <base>...HEAD --stat              # the commits of the branch: what the pull request will contain
git diff <base>...HEAD
git diff HEAD                              # local changes to tracked files
git ls-files --others --exclude-standard   # untracked files, which no git diff shows
```

- Keep the branch diff and the local changes apart. If the worktree is not clean, include a local change only if it
  will be committed with the pull request; when that is unclear, ask the user.
- Read the untracked files that are part of the change.
- Read the issue or the request, to know what the change must do. If the change was planned with Spec Kit, read
  `specs/<feature>/` (`spec.md`, `plan.md`, `tasks.md`, the red-team findings) and check that the steps the
  constitution makes mandatory ran: the red-team gate decision or its waiver in `plan.md` (Principle VIII), and the
  security reviews when the change touches an area of a Critical-tier invariant (Principle IX).
- Find the invariants that govern the touched code: `grep -n '<touched file or symbol>' docs/specification/invariant.md`
  lists the entries whose `Enforced in` names it, and their `Tests` field points at the tests. Read the matching
  sections of `permissions.md`, `advisory-lifecycle.md` and `architecture.md`.
- Then read in full the files the change touches, the callers of every changed function, the other views, services
  and tasks that follow the same pattern, and the tests that cover them.

## 2. Attack the change

Answer each question that applies to the files touched. A "no" or an "I don't know" is a lead to verify, not a
finding.

1. **Who can reach it, and is it checked on the server?** (`INV-AUTH-1`.) For every new or changed view, HTMX
   endpoint, API handler, form, Celery task and management command, find the predicate of `advisories/permissions.py`
   that gates it, and check that it runs on the `POST` path, on the form-error re-render and in HTMX partials (see
   `advisories/tests/test_authz_error_disclosure.py`), and in a task when it runs, not only when it is enqueued.
   Hiding a button in a template is not a check. Walk the capability matrix of `permissions.md`: anonymous, outsider,
   provisioned shadow user (`INV-OIDC-5`), banned user (`INV-AUTH-8`), viewer, collaborator, owner through the security
   team, global admin (who cannot submit for review, `INV-REVIEW-3`); and the state-conditioned overrides: triage
   (`INV-AUTH-5`), admin-routing flag (`INV-AUTH-6`), `review_status=submitted` (`INV-REVIEW-2`, `INV-PERM-3`),
   published without a grant (`INV-AUTH-7`), dismissed, and the step-up and mature-publisher gates. Look for IDOR: a
   nested id (comment, grant, invitation, task, version) looked up without checking that it belongs to the advisory
   in the URL. Counts, search results, pagination totals and an error that tells "does not exist" from "not
   allowed" must not reveal an advisory the caller cannot see (`INV-PRIVACY-1`).
   Authorization reads the DB mirror, never a client-submitted value: `permission="owner"`, a group name, a project
   id, `is_internal` (`INV-OIDC-2`, `INV-AUTH-3`, `INV-ACCESS-4`, `INV-COMMENT-1`). The generic sweep of
   `tests/test_authorization_matrix.py` only finds the routes whose only argument is `advisory_id`: any other route
   needs explicit cases there.
2. **Does it still hold below the application?** (`INV-CONF-2`.) Row-level security is dormant in dev and CI, because
   the bootstrap Postgres role is a superuser, and active in production under a non-superuser role. A bug here passes
   every test that does not switch role the way `advisories/tests/test_rls.py` does (`SET ROLE` to a throwaway
   `NOSUPERUSER` role). A Celery task, a management command or a data migration that reads advisories or their child
   tables without `common.rls.rls_principal` or `rls_system` sees no rows in production: it reports "nothing to do"
   instead of failing. A new table with an `advisory_id` foreign key that holds advisory content needs a decision,
   recorded in the spec: the deferring child policy (`_CHILD_TABLES` of `advisories/migrations/0010_advisory_rls.py`,
   added by a new migration), or the application layer only, as for the workflow, publication, notification,
   similarity and GHSA tables today. A change to `AdvisoryQuerySet.visible_to` needs the same change to the policy, or
   `test_rls_matches_visible_to` drifts. RLS catches a forgotten filter, not a wrong predicate.
3. **Is every mutation versioned, audited and paused?** A content edit goes through the service layer and appends
   `AdvisoryVersion` v(n+1); a state-only flip does not (`INV-VERSION-1`). A new field in `Advisory.to_payload()` is
   versioned automatically: check what it then changes in the OSV and CSAF exports, the version diff and
   `republish_required`. A field left out of `to_payload()` that changes published content is a bug. Editing a draft
   resets its approval (`INV-REVIEW-4`); editing a published advisory sets `republish_required`. Every governance or
   grant change writes an `AuditLogEntry` (`INV-AUDIT-3`, `INV-ACCESS-5`), with IP and user agent when it comes from
   the web (`INV-AUDIT-4`). `QuerySet.update()`, `bulk_create()`, `bulk_update()` and a direct `.save()` skip the
   service layer and its audit. `AdvisoryVersion`, `AuditLogEntry` and `CommentVersion` are never updated or deleted
   (`INV-AUDIT-1`, `INV-IMPL-*`). `common.middleware.MaintenanceModeMiddleware` lets safe methods and
   `_EXEMPT_PREFIXES` through: a mutation reachable by `GET` or under an exempt prefix escapes maintenance mode
   (`INV-MAINT-1`) and CSRF.
4. **Does each transition match `advisory-lifecycle.md`, even under concurrency?** Four states only
   (`INV-LIFECYCLE-1`), review as a separate sub-machine (`INV-REVIEW-1`), plus the CVE-request and publication-task
   sub-machines. For each new or changed transition: is it in the transition table, from which states, and who may
   trigger it? Then replay it twice: two tabs, a double click, the back button, two workers. Celery delivers at least
   once, so a task may run twice, or after the state changed: it must re-read and re-check under `select_for_update`
   when it runs. A uniqueness or write-once rule (`INV-ACCESS-1`, `INV-CVE-1`, `INV-CVE-2`, `INV-ID-1`, `INV-ID-2`) is
   held by a database constraint or a lock, not by a check-then-insert. A version write and its state flip share one
   transaction (`INV-CONCURRENCY-2`). Nothing deletes an advisory: a published one is withdrawn (`INV-WITHDRAW`,
   `INV-IMPL-1`).
5. **Does the publication stay consistent with the Git repository when a step fails?** (`INV-LIFECYCLE-3`,
   `INV-PUB-*`.) `state` flips to `published` only after a successful push, in the same transaction as the task
   outcome (`INV-PUB-4`). Make each step fail in turn: build, schema validation (`INV-PUB-6`), clone, write, commit,
   push rejected because another publication pushed first, and a push that landed while the worker died before the
   finalisation. Each time the advisory keeps its prior state, the `PublicationTask` is `failed` with a redacted
   `last_error`, and a retry converges: a new task, no duplicate commit, and a retry that finds the files already in
   the repository ("nothing to commit") must not stay failed forever. The exports are built from the version pinned
   on the task, never from live data (`INV-VERSION-3`), and are written inside the clone (`INV-PUB-8`), even when an
   id ends up in a path. A single publication is in flight per advisory (`INV-CONCURRENCY-1`), the task is enqueued
   with `transaction.on_commit` (`INV-PUB-5`) so a rolled-back request enqueues nothing, and a stale task is reaped
   (`INV-PUB-7`). Withdrawal, un-withdrawal, the system publish and GHSA auto-publish follow the same rules. Check it
   with the local bare repository and a monkeypatched failure, as `test_advisory_state_does_not_flip_until_after_push`
   and `test_withdrawal_retry_after_failed_push` in `publication/tests/test_pipeline.py` do.
6. **What does it do when an external system fails or answers partially?** GitHub (GHSA), the PMI API (roster sync),
   the OIDC claims, the LLM provider, the mail server, Valkey and the publication remote may answer 403, 404, 5xx, time
   out or fail on one page of a paginated list. An empty answer that the system confirms and an incomplete read are
   different cases. An incomplete read must never become a removal: no shadow user, group membership, grant, project
   link or GHSA state dropped because a read failed. Every outbound call has a timeout, so a request never hangs on
   it. An unexpected status fails explicitly instead of passing as an empty result, and its error is redacted. In a
   batch (beat jobs, roster sync, backfills), check whether one failing project or advisory stops the others when it
   should not. The user sees a message, not a traceback or a bare 500, including in HTMX partials.
7. **Can outside input reach it, and can a secret or content leave?** Untrusted input: the public intake `/report/`
   (honeypot `INV-INTAKE-1`, no reporter email `INV-INTAKE-2`, rate limit before the operation `INV-RATELIMIT-1`),
   GHSA webhook payloads (HMAC-checked before any side effect), PMI roster data, advisory and comment content
   rendered in templates (`|safe`, `mark_safe`, Markdown) or written into OSV/CSAF, commit messages and file paths, and
   LLM output in `similarity/`, which may carry injected instructions and must never drive authorization or state
   (`INV-SIM-1`). Every user- or CI-supplied string goes through `audit.services.redact_secrets` before it reaches a
   log, audit metadata, a task error, an artifact or a notification (`INV-AUDIT-2`, `INV-SECRET-*`), and
   token-rewritten URLs through `publication.git_service._redact`; watch exceptions whose message embeds a URL or a
   header. No content reaches the LLM provider while `SIMILARITY_CHECK_ENABLED` is off (`INV-SIM-2`), and its API key
   never persists (`INV-SIM-3`). Notification recipients are re-checked when the mail is sent (`INV-PRIVACY-2`),
   internal comments stay hidden from viewers (`INV-COMMENT-2`), and other users' emails are shown to owners only
   (`INV-PRIVACY-4`). In `.github/workflows/`, check the `${{ }}` expressions in `run:` steps, the job permissions and
   the conventions of `CLAUDE.md` (SHA-pinned `uses:`, harden-runner, `persist-credentials: false`, `env:`
   indirection).
8. **Does the page still work under the enforced CSP?** (Principle VII.) No inline `on*=` handler, `hx-on`,
   per-element `hx-headers`, `style="…"` or `<style>`; any inline `<script>` carries the nonce; assets come from
   `{% static %}`; no multi-line `{# #}`. A violation fails no test, it breaks the page in the browser:
   `git diff <base>...HEAD -- '*.html' '*.js' | grep -nE '^\+.*(style=|<style|[[:space:]]on[a-z]+=|hx-on|hx-headers|<script)'`
   finds the candidates. If the dev stack is running, load the changed pages and read the browser console; otherwise
   say in the report that the CSP was checked statically only.
9. **Do all the homes of the change agree?** One forgotten home is the most common bug.
   - Behaviour: the canonical spec in the same pull request (Principle I): `invariant.md` (`Enforced in` and `Tests`
     still name existing files and symbols), `permissions.md`, `advisory-lifecycle.md`, `architecture.md` (pipelines,
     beat schedule, environment variables), `requirements.md`; then the manual in `docs/manual/` and `CLAUDE.md`.
   - An endpoint under `/api/`, the GHSA webhook, the intake project picker or a health probe: `openapi.yaml`, drift-
     guarded by `api/tests/test_openapi_spec.py`.
   - A configuration knob: `config/settings/base.py`, `.env.example`, the Helm chart (`values.yaml`,
     `values.schema.json`, the `advisoryhub.envMap` mapping; a secret only as an expected key of the env Secret,
     documented in the chart README, never in the ConfigMap), `docs/operations/configuration.md`, and the
     `x-django-env` anchor of `docker-compose.yml` when dev needs it.
   - Personal data in a new model or field: `forget_user` and the retention pruning reach it.
   - Vendored assets change only through `dev/update_vendored_assets.py`; the generated `.claude/skills/speckit-*/`
     and `.specify/` files only through the Specify CLI.
10. **Does every existing deployment upgrade cleanly?** A migration runs on a production database with rows: a new
    non-null column, a backfill or a data migration on a large table, a constraint that existing rows violate. A data
    migration that reads advisories needs the RLS principal (question 2). No migration drops or replaces the
    append-only triggers or the RLS policies without restoring them. Say whether it can be reversed. A renamed
    setting, a changed default or a new required setting breaks operators: the migration path goes in the pull request
    description, and the commit is marked breaking (`!` or `BREAKING CHANGE:`) so git-cliff reports it. A change to
    the OSV or CSAF builders changes the files of every published advisory at its next republish: check that this is
    intended and that the output still validates against the vendored schemas.
11. **Does each new test fail without the change, for the expected reason?** Run it against the old implementation in
    an isolated environment that leaves the shared checkout and its test database untouched, for example a temporary
    worktree with its own test database. Breaking the code by hand instead can make the test fail for another reason.

    ```shell
    git worktree add --detach <tmp-dir> <base>                # outside the checkout
    cp <new test files and fixtures> <tmp-dir>/<same paths>
    cd <tmp-dir> && TEST_DATABASE_URL=postgres://advisoryhub:advisoryhub@localhost:5432/advisoryhub_base \
        <checkout>/.venv/bin/python -m pytest --create-db <test files>
    git worktree remove --force <tmp-dir>
    ```

    The virtual environment of the checkout is reused: the project is not installed in it, and `python -m pytest`
    puts the current directory first on `sys.path`, so the old code is tested. The other database name gives the old
    code its own test database (`test_advisoryhub_base`), built from the old migrations, and `--create-db` overrides
    the `--reuse-db` of `addopts`; the `test_advisoryhub` database of the checkout is not touched. Postgres must be up
    (`docker compose up -d postgres`). The test must fail on the assertion that targets the regression, not on an
    import error, a missing migration or a missing fixture. When it cannot run against the old code, say exactly why
    in the report.
    Check also that the tests cover the denied roles, the other states and the failure paths above, not only the
    expected path, that they run on PostgreSQL, and that they reach no network, real OIDC provider, mail server or
    Git remote.
12. **Does the branch hold only this change, and do its commits follow the policy?** No unrelated change, no debug
    leftover (`print`, `breakpoint()`), no generated or vendored file edited by hand, and no local file that must
    never be committed (`.env`, `dev/kanidm/.env.kanidm`, `mise.local.toml`, `TODO.md`, `sbom.cdx.json`, keys, the
    local state under `.claude/`). Each commit follows Conventional Commits, is signed and signed-off, cites the
    `INV-*` IDs it touches, carries `Assisted-by:` when an AI wrote it and no `Co-Authored-By:`:
    `git log --format='%h %G? %s%n%(trailers:key=Signed-off-by,key=Assisted-by,key=Co-Authored-By)' <base>..HEAD`
    (`%G?` is `N` for an unsigned commit, and `E` for a signature that cannot be verified locally).

## 3. Classify the findings

- **Confirmed**: traced through the code or reproduced by a test, on the state reviewed.
- **Open hypothesis**: credible but not reproduced. Say what is missing to settle it.
- **Dismissed**: the lead did not hold.

## 4. Verdict and report

The verdict comes first, with its reason:

- **`ready`**: no confirmed finding against the change, and the checks it needs ran and passed, including the Spec
  Kit reviews the constitution makes mandatory for it.
- **`blocked`**: at least one confirmed bug, or a required check fails. The pull request is not opened until it is
  fixed.
- **`inconclusive`**: a point that decides could not be settled (a check could not run, a scenario could not be
  reproduced, the scope is unclear). Say what is missing, and let the user decide.

Then:

- the state reviewed: the commit, and the local changes included;
- the confirmed findings, first: `file:line`, failure scenario, evidence (test or trace), the `INV-*` ID and tier
  when one is broken, and whether the finding concerns only local changes;
- the open hypotheses, only if they change the decision to open the pull request;
- the dismissed leads only when their explanation helps the reviewer of the pull request;
- the checks that ran and their results, and the checks that were skipped, with the reason;
- the points for the description of the pull request: the `INV-*` IDs and spec sections touched, the risky areas, the
  open hypotheses, and what was not tested (for example RLS under a non-superuser role, the CSP in a browser, a real
  OIDC provider or Git remote).

## 5. Fix pass, on request

When the user asks for the confirmed bugs to be fixed:

1. Fix them and add a regression test for each one, checked as in question 11. When the fix changes behaviour,
   update the canonical spec in the same change.
2. Leave design and behaviour choices to the user: describe the options instead of choosing one silently. A fix
   never works around an invariant or deviates from the spec: when the right fix would, stop and raise it, since that
   needs maintainer confirmation first (Principles I and II).
3. Run the checks of `CLAUDE.md` again for the files touched, review the new diff, and give a new verdict.

Commit, push or open the pull request only when the user asks, following the commit policy of `CLAUDE.md`.
