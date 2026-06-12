# Configuration

AdvisoryHub is configured entirely through **environment variables**, parsed by
`django-environ` in `config/settings/base.py`. This page documents the settings
modules and the complete variable catalogue.

Two reference files back this page:

- **`.env.example`** — an annotated reference of the production knobs, grouped and
  marked *secret* vs *config*. It is **not** loaded by docker-compose; it exists to
  copy into your platform's secret manager.
- **`config/settings/base.py`** — the authoritative schema (defaults and types). A
  few knobs are read here but omitted from `.env.example`; those rows are marked
  **†** below.

Legend: **Secret** = must come from a vault, never a committed manifest.
**Required** = has no usable production default. **†** = read by `base.py` but not
listed in `.env.example`.

---

## 1. Settings modules

`config/settings/` holds four modules; the active one is chosen by
`DJANGO_SETTINGS_MODULE`:

| Module | Selected by | Purpose |
|---|---|---|
| `config.settings.base` | (imported by the others) | The full env-driven schema, apps, middleware, security defaults, OIDC, Celery, CSP, the beat schedule. |
| `config.settings.dev` | `manage.py` and `config/celery.py` default | `DEBUG=True`, HTTP cookies, relaxed hosts. |
| `config.settings.prod` | `config/wsgi.py` and `config/asgi.py` default | `DEBUG=False`, HSTS + SSL redirect, WhiteNoise compressed/manifest static, Prometheus multiprocess notes. |
| `config.settings.test` | `pyproject.toml` (pytest) | Eager Celery, rate-limiting and step-up off, fast password hasher. |

In production, run the WSGI/ASGI app (which defaults to `prod`) or set
`DJANGO_SETTINGS_MODULE=config.settings.prod` explicitly for management commands.
What `prod.py` changes is detailed in
[running-in-production.md](./running-in-production.md).

---

## 2. Django core

| Variable | Default | Notes |
|---|---|---|
| `DJANGO_SECRET_KEY` | `insecure-change-me` | **Secret. Required.** Session/CSRF signing key — a long random string. |
| `DJANGO_DEBUG` | `False` | Never `True` in production. |
| `DJANGO_ALLOWED_HOSTS` | `*` | **Required.** Comma-separated hostnames, e.g. `advisoryhub.example.org`. |
| `DJANGO_TIME_ZONE` | `UTC` | Keep `UTC`. |

## 3. Database & cache

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgres://advisoryhub:advisoryhub@localhost:5432/advisoryhub` | **Secret. Required.** Must be PostgreSQL — append-only triggers and JSONB are Postgres-specific. |
| `CACHE_URL` | *(empty → in-process LocMem)* | **Required in prod.** Point at the shared Valkey, e.g. `redis://valkey:6379/2`. Backs rate-limiting and the maintenance-mode flag; LocMem is per-process and won't coordinate across replicas. |

## 4. OIDC (authentication)

See [integrations.md §1](./integrations.md#1-oidc-identity-provider) for the
end-to-end setup. All endpoints come from your provider's discovery document.

| Variable | Default | Notes |
|---|---|---|
| `OIDC_RP_CLIENT_ID` | *(empty)* | **Required.** Confidential-client id for this environment. |
| `OIDC_RP_CLIENT_SECRET` | *(empty)* | **Secret. Required.** |
| `OIDC_OP_AUTHORIZATION_ENDPOINT` | *(empty)* | **Required.** Browser-facing authorize URL. |
| `OIDC_OP_TOKEN_ENDPOINT` | *(empty)* | **Required.** Server-to-server token exchange. |
| `OIDC_OP_USER_ENDPOINT` | *(empty)* | **Required.** Userinfo endpoint. |
| `OIDC_OP_JWKS_ENDPOINT` | *(empty)* | **Required.** Signing-key (JWKS) endpoint. |
| `OIDC_OP_LOGOUT_ENDPOINT` | *(empty)* | Optional. The OP `end_session_endpoint` for RP-initiated logout; empty falls back to local-only logout. |
| `OIDC_RP_SIGN_ALGO` | `RS256` | ID-token signature algorithm (dev Kanidm uses `ES256`). |
| `OIDC_VERIFY_SSL` | `True` | Keep `True` in prod; dev sets `False` for Kanidm's self-signed cert. |
| `OIDC_USE_PKCE` † | `True` | PKCE (`S256`); most modern providers require it. |
| `OIDC_GROUP_CLAIM` | `groups` | The claim carrying group membership. |
| `OIDC_ADMIN_GROUP` | `advisoryhub-security` | Membership grants global admin + Django `is_staff`/`is_superuser`. |

## 5. Step-up authentication

| Variable | Default | Notes |
|---|---|---|
| `STEP_UP_REQUIRED` | `True` | Force a fresh re-login before publishing / GitHub-App changes. Keep `True` in prod. |
| `STEP_UP_MAX_AGE_SECONDS` | `300` | How recent that re-auth must be. |

## 6. Celery & broker

| Variable | Default | Notes |
|---|---|---|
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | **Secret (if AUTH). Required.** In prod prefer `rediss://:<pw>@host:6379/0`. |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/1` | Results are ignored (`CELERY_TASK_IGNORE_RESULT=True`), so this DB stays empty. |
| `CELERY_TASK_ALWAYS_EAGER` | `False` | Run tasks inline — test-only; never `True` in prod. |

## 7. Email

| Variable | Default | Notes |
|---|---|---|
| `EMAIL_BACKEND` | `…console.EmailBackend` | Set to `django.core.mail.backends.smtp.EmailBackend` in prod, then configure the `EMAIL_HOST*` knobs below. |
| `DEFAULT_FROM_EMAIL` | `AdvisoryHub <noreply@example.org>` | From-address on outbound notifications. |
| `EMAIL_HOST` | `localhost` | SMTP relay host (smtp backend only). |
| `EMAIL_PORT` | `25` | SMTP port — typically `587` with STARTTLS. |
| `EMAIL_HOST_USER` | *(empty)* | SMTP auth username; empty disables auth. |
| `EMAIL_HOST_PASSWORD` | *(empty)* | **Secret.** SMTP auth password. |
| `EMAIL_USE_TLS` | `False` | STARTTLS on connect (mutually exclusive with `EMAIL_USE_SSL`). |
| `EMAIL_USE_SSL` | `False` | Implicit TLS (usually port `465`). |
| `ADVISORYHUB_BASE_URL` | *(empty)* | Absolute-URL base for links in notification emails, e.g. `https://advisoryhub.example.org`. Empty keeps links site-relative (they won't resolve from a mail client). |

## 8. Publication Git repository

See [integrations.md §2](./integrations.md#2-publication-git-repository).

| Variable | Default | Notes |
|---|---|---|
| `PUB_REPO_URL` | *(empty)* | **Required to publish.** SSH (`git@…`) or HTTPS URL. |
| `PUB_REPO_BRANCH` | `main` | Branch to push to. |
| `PUB_REPO_AUTH` | `ssh` | `ssh` or `token`. |
| `PUB_REPO_SSH_KEY_PATH` | *(empty)* | **Secret. Required if `ssh`.** Path to the deploy private key, e.g. `/run/secrets/pub_repo_ssh_key`. |
| `PUB_REPO_TOKEN` | *(empty)* | **Secret. Required if `token`.** PAT/access token (stripped from every error, audit, and notification surface). |
| `PUB_COMMIT_AUTHOR_NAME` | `AdvisoryHub Bot` | Commit author name. |
| `PUB_COMMIT_AUTHOR_EMAIL` | `advisoryhub-bot@example.org` | Commit author email. |
| `PUB_OSV_PATH_TEMPLATE` | `osv/{year}/{advisory_id}.json` | OSV output path; placeholders `{year}`, `{advisory_id}`. |
| `PUB_CSAF_PATH_TEMPLATE` | `csaf/{year}/{advisory_id}.json` | CSAF output path. |
| `PUB_CVE_PATH_TEMPLATE` | `cves/{year}/{bucket}/{cve_id}.json` | CVE-record path (mirrors the cvelistV5 layout); placeholders `{year}`, `{bucket}`, `{cve_id}`. |
| `PUB_CVE_ASSIGNER_ORG_ID` | *(empty)* | **Required to publish a CVE-assigned advisory.** The EF CNA's v4 UUID — publishing fails loudly while empty. |
| `PUB_CVE_ASSIGNER_SHORT_NAME` | `eclipse` | CNA short name written into the CVE record. |

## 9. GHSA / GitHub App & PMI

Off by default. See [integrations.md §3](./integrations.md#3-ghsa--github-app-optional).

| Variable | Default | Notes |
|---|---|---|
| `GHSA_FEATURE_ENABLED` | `False` | Master switch for the GitHub Security Advisory integration. |
| `GITHUB_APP_ID` | `0` | **Required if enabled.** Numeric GitHub App id. |
| `GITHUB_APP_PRIVATE_KEY_PATH` | *(empty)* | **Secret. Preferred.** File path to the App private key, e.g. `/run/secrets/github_app_private_key`. |
| `GITHUB_APP_PRIVATE_KEY` | *(empty)* | **Secret.** Inline key — dev fallback only; leave empty in prod. |
| `GITHUB_APP_WEBHOOK_SECRET` | *(empty)* | **Secret.** HMAC key verifying inbound webhooks. |
| `GITHUB_APP_API_BASE_URL` | `https://api.github.com` | Override for GitHub Enterprise. |
| `PMI_API_BASE_URL` | `https://projects.eclipse.org/api` | Eclipse PMI (project↔repo) API. |
| `PMI_API_TOKEN` | *(empty)* | **Secret (if set).** Usually blank — PMI is public. |
| `PMI_SYNC_INTERVAL_HOURS` | `6` | Beat cadence for the repo-mirror refresh. |

## 10. Security-team roster sync

Off by default. See [integrations.md §4](./integrations.md#4-security-team-roster-sync-optional).

| Variable | Default | Notes |
|---|---|---|
| `PMI_ROSTER_SYNC_ENABLED` | `False` | Pre-provision notification-only shadow users for security-team members. |
| `PMI_ROSTER_SYNC_INTERVAL_HOURS` | `24` | Beat cadence for roster refresh. |
| `ECLIPSE_API_BASE_URL` | `https://api.eclipse.org` | Authenticated Eclipse API base. |
| `ECLIPSE_API_TOKEN_URL` | `https://auth.eclipse.org/auth/realms/eclipse/protocol/openid-connect/token` | OAuth2 client-credentials token endpoint. |
| `ECLIPSE_API_CLIENT_ID` | *(empty)* | **Secret. Required if enabled.** |
| `ECLIPSE_API_CLIENT_SECRET` | *(empty)* | **Secret. Required if enabled.** |
| `ECLIPSE_API_SCOPE` | *(empty)* | Optional space-separated scope(s). |

## 11. LLM duplicate detection (similarity)

Off by default. See [integrations.md §5](./integrations.md#5-similarity-llm-provider-optional).
Enabling the switch **is the consent** for advisory content (potentially embargoed)
to reach the configured LLM provider ([INV-SIM-2]).

| Variable | Default | Notes |
|---|---|---|
| `SIMILARITY_CHECK_ENABLED` | `False` | Master switch for LLM-assisted duplicate detection. |
| `SIMILARITY_LLM_PROVIDER` | `anthropic` | `anthropic` or `openai` (incl. OpenAI-compatible servers). |
| `SIMILARITY_LLM_MODEL` | `claude-opus-4-8` | Model identifier for the selected provider. |
| `SIMILARITY_LLM_API_KEY` | *(empty)* | **Secret. Required if enabled** — blank only for keyless local servers. |
| `SIMILARITY_LLM_BASE_URL` | *(empty)* | Empty = provider default; point at a local OpenAI-compatible server (e.g. `http://ollama:11434`) for on-prem inference. |
| `SIMILARITY_LLM_TIMEOUT` | `120` | Per-request read timeout in seconds (connect timeout is fixed at 10). |
| `SIMILARITY_CANDIDATE_LIMIT` | `60` | Max prefiltered candidates sent to the LLM judge call. |
| `SIMILARITY_MIN_CONFIDENCE` | `20` | Store matches at/above this confidence (0–100). |

## 12. Public report intake

| Variable | Default | Notes |
|---|---|---|
| `HCAPTCHA_SITE_KEY` † | *(empty)* | hCaptcha on the public form; captcha is bypassed unless **both** keys are set. |
| `HCAPTCHA_SECRET_KEY` † | *(empty)* | **Secret.** |
| `RATELIMIT_INTAKE_ANON` † | `5/h` | Per-IP limit for anonymous report submission. |
| `RATELIMIT_INTAKE_USER` † | `20/h` | Per-user limit for authenticated submission. |
| `INTAKE_REPORT_RETENTION_DAYS` † | `365` | Horizon after which intake PII is scrubbed (see `prune_reports`). |
| `INTAKE_DISABLED` † | `False` | Kill switch for the public `/report/` form. |

## 13. Logging & reverse proxy

| Variable | Default | Notes |
|---|---|---|
| `LOG_FORMAT` | `json` | `json` (prod) or `plain` (dev). |
| `LOG_LEVEL` | `INFO` | Root log level. |
| `TRUSTED_PROXY_COUNT` | `0` | Number of trusted proxies appending to `X-Forwarded-For`. Set to your real proxy depth (e.g. `1`) so per-IP rate limits and audit IPs reflect the true client and can't be spoofed. `0` ignores the header. |
| `USE_X_FORWARDED_PROTO` | `False` | Trust the proxy's `X-Forwarded-Proto` (sets `SECURE_PROXY_SSL_HEADER`). **Required when TLS terminates at the proxy** — without it `SECURE_SSL_REDIRECT` loops and secure cookies/CSRF never engage. Only enable when *all* traffic passes a proxy that sets (never forwards) the header. |
| `CSRF_TRUSTED_ORIGINS` | *(empty)* | Comma-separated origins for CSRF origin checking behind a proxy, e.g. `https://advisoryhub.example.org`. Pair with `USE_X_FORWARDED_PROTO`. |

> `/healthz`, `/readyz` and `/metrics` are exempt from the prod SSL redirect
> (`SECURE_REDIRECT_EXEMPT` in `base.py`) so plain-HTTP kubelet probes and
> Prometheus scrapes see real status codes instead of 301s.

## 14. Observability

See [observability.md](./observability.md).

| Variable | Default | Notes |
|---|---|---|
| `SENTRY_DSN` | *(empty)* | **Secret.** Empty disables Sentry. |
| `SENTRY_ENVIRONMENT` | *(unset)* | Environment tag, e.g. `production`. |
| `SENTRY_TRACES_SAMPLE_RATE` | `0` | Tracing sample rate (0.0–1.0). |
| `SENTRY_RELEASE` † | *(unset)* | Optional release tag on Sentry events. Read straight from the OS env (`common/sentry.py`). |
| `PROMETHEUS_WORKER_METRICS_PORT` | `0` | Set **on the worker only** (compose uses `9808`); `0` disables its exporter. |
| `PROMETHEUS_MULTIPROC_DIR` | *(unset)* | **Required for multi-worker gunicorn.** A writable, empty-at-boot tmpfs so the custom `advisoryhub_*` counters aggregate across workers. Read straight from the OS env. |

## 15. CSP, rate-limiting, health, audit retention

| Variable | Default | Notes |
|---|---|---|
| `CSP_REPORT_ONLY` | `False` | CSP is **enforced** by default; set `True` for Report-Only while diagnosing a new violation. |
| `CSP_REPORT_URI` | *(empty)* | Optional collector URL for the `report-uri` directive. |
| `RATELIMIT_ENABLE` | `True` | Master rate-limit switch (dev/test set `False`). |
| `READYZ_INCLUDE_BROKER` | `False` | Add a Celery-broker probe to `/readyz`. |
| `READYZ_INCLUDE_PUB_REPO` | `False` | Add a `git ls-remote` of the publication repo to `/readyz`. |
| `AUDIT_ACCESS_LOG_RETENTION_DAYS` | `90` | Drop access-log monthly partitions older than this. |
| `AUDIT_ACCESS_LOG_RETENTION_ENABLED` | `True` | Enable the daily partition-maintenance task. |

> Security headers (`__Host-` cookies, HSTS, SSL redirect, `X-Frame-Options`,
> nonce CSP, Permissions-Policy) are set in code (`base.py` / `prod.py`), not via
> env vars — see [running-in-production.md §6](./running-in-production.md#6-security-hardening-checklist).
