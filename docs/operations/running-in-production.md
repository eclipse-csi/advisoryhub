# Running in production

How to run the three processes, front them correctly, wire health probes, and
harden the deployment. Configuration lives in [configuration.md](./configuration.md);
integrations in [integrations.md](./integrations.md).

---

## 1. Process topology

Run three long-lived processes, all from the same image and the same environment:

| Process | Command | Scale |
|---|---|---|
| **web** | `gunicorn config.wsgi -c gunicorn.conf.py` | Horizontal — many replicas behind the proxy. |
| **worker** | `celery -A config worker -l info --pool=threads --concurrency=N` | Horizontal. |
| **beat** | `celery -A config beat -l info` | **Exactly one** instance. |

> **Settings-module gotcha.** `config/wsgi.py`/`asgi.py` default to
> `config.settings.prod`, but `config/celery.py` defaults to **`config.settings.dev`**.
> Always export **`DJANGO_SETTINGS_MODULE=config.settings.prod`** for the worker and
> beat (and ideally for every process) so they don't silently run dev settings.

**web** — gunicorn with this repo's `gunicorn.conf.py` (its `child_exit` hook reaps
Prometheus multiprocess files). Set `PROMETHEUS_MULTIPROC_DIR` to a writable,
empty-at-boot tmpfs so the custom `advisoryhub_*` counters aggregate across
workers; choose `--workers`/`--bind` to taste:

```sh
export DJANGO_SETTINGS_MODULE=config.settings.prod
export PROMETHEUS_MULTIPROC_DIR=/run/prometheus     # tmpfs, empty at boot
gunicorn config.wsgi -c gunicorn.conf.py --workers 4 --bind 0.0.0.0:8000
```

**worker** — use `--pool=threads` so a single Prometheus exporter sees every task
thread (the tasks are I/O-bound: git push, GitHub/PMI API, email). Set
`PROMETHEUS_WORKER_METRICS_PORT` to expose its exporter:

```sh
export DJANGO_SETTINGS_MODULE=config.settings.prod
export PROMETHEUS_WORKER_METRICS_PORT=9808
celery -A config worker -l info --pool=threads --concurrency=4
```

**beat** — fires the periodic tasks (§5). Run a single instance; if the filesystem
is read-only or ephemeral, point its schedule file somewhere writable with
`--schedule=/var/run/celerybeat-schedule`.

> Task semantics: publication is enqueued on `transaction.on_commit` (so a row is
> never published before its DB transaction lands) and runs `acks_late`, so a task
> redelivers if a worker dies mid-flight. A failed publish leaves the advisory's
> state unchanged ([INV-LIFECYCLE-3]).

---

## 2. Reverse proxy & TLS

`web` expects to sit behind a TLS-terminating reverse proxy / load balancer:

- Terminate HTTPS upstream and forward to gunicorn.
- Set **`DJANGO_ALLOWED_HOSTS`** to your real hostname(s).
- `prod.py` enables **`SECURE_SSL_REDIRECT`** and HSTS. Because TLS terminates
  at the proxy, set **`USE_X_FORWARDED_PROTO=True`** so Django trusts the
  proxy's `X-Forwarded-Proto` — without it every request 301-loops. Only enable
  it when all traffic passes a proxy that sets (never forwards) that header.
- Set **`CSRF_TRUSTED_ORIGINS`** to the public origin(s), e.g.
  `https://advisoryhub.example.org`, so CSRF origin checking accepts form posts
  arriving via the proxy.
- `/healthz`, `/readyz` and `/metrics` are exempt from the SSL redirect
  (`SECURE_REDIRECT_EXEMPT`): plain-HTTP kubelet probes and Prometheus scrapes
  get real status codes — a 301 would count as a passing probe while skipping
  the actual readiness checks.
- Set **`TRUSTED_PROXY_COUNT`** to the number of proxies in front of the app so
  per-IP rate limits and audit-log client IPs use the true client address and
  can't be spoofed via a forged `X-Forwarded-For`.
- Keep `/metrics` off the public ingress (§ observability).

---

## 3. Static files

Static assets are served by **WhiteNoise** directly from the app — no separate
static host or CDN, and no third-party asset origins.

- Run **`python manage.py collectstatic --noinput`** at build/release time. It
  hashes filenames and precompresses (gzip + brotli) into `STATIC_ROOT`
  (`staticfiles/`).
- `prod.py` selects `CompressedManifestStaticFilesStorage` and inserts
  `WhiteNoiseMiddleware` right after `SecurityMiddleware`; hashed assets are served
  with a 1-year immutable `Cache-Control`.
- Vendored assets (htmx, the Inter font) are checked in and integrity-verified by
  `dev/check_vendored_assets.sh`; there is no font/script CDN.

Never serve production static through the dev runserver.

---

## 4. Health & readiness

Two unauthenticated, CSRF-exempt `GET` endpoints (`common/health.py`):

| Endpoint | Use | Behaviour |
|---|---|---|
| `/healthz` | **Liveness** probe | Always `200 {"status":"ok"}` if the process answers — no dependency checks. |
| `/readyz` | **Readiness** probe | `200` only if every enabled check passes; otherwise `503` with `{"status":"fail","failures":{…}}`. |

`/readyz` always probes the **database** and the **cache**. It additionally probes:

- the **Celery broker** when `READYZ_INCLUDE_BROKER=True` (recommended in prod —
  `safe_enqueue` swallows broker outages, so without this a down broker is
  invisible and enqueued work sits queued forever);
- the **publication repo** (`git ls-remote`) when `PUB_REPO_URL` is set **and**
  `READYZ_INCLUDE_PUB_REPO=True` (off by default — it egresses to the remote on
  every probe).

Wire your orchestrator's liveness probe to `/healthz` and its readiness probe to
`/readyz`.

---

## 5. The Celery beat schedule

`beat` fires four periodic tasks (defined in `config/settings/base.py`):

| Schedule entry | Task | Cadence | Purpose |
|---|---|---|---|
| `pmi-repo-mirror` | `ghsa.tasks.run_pmi_repo_sync` | every `PMI_SYNC_INTERVAL_HOURS` (6h) | Refresh the project↔repo mirror from Eclipse PMI. |
| `access-log-partition-maintenance` | `audit.tasks.maintain_access_log_partitions` | daily | Create the upcoming month's access-log partition; drop expired ones (no-op when retention disabled). |
| `backlog-gauge-refresh` | `audit.tasks.refresh_backlog_gauges` | every 60s | Refresh the `advisoryhub_backlog` Prometheus gauge from live counts. |
| `security-roster-sync` | `projects.tasks.run_roster_sync` | every `PMI_ROSTER_SYNC_INTERVAL_HOURS` (24h) | Refresh security-team rosters (no-op unless `PMI_ROSTER_SYNC_ENABLED`). |

The PMI mirror and roster cadences follow their interval env vars; the other two
are fixed. Without a running `beat`, none of these fire — notably the backlog
gauge stays empty.

---

## 6. Security hardening checklist

Most hardening is on by default in `prod.py` / `base.py`; verify and complete:

- [ ] Run **`python manage.py check --deploy --fail-level WARNING`** in your release
      pipeline — it flags missing/weak security settings.
- [ ] `DEBUG=False`, `DJANGO_ALLOWED_HOSTS` set to real hosts.
- [ ] Cookies: `SESSION_COOKIE_SECURE`/`CSRF_COOKIE_SECURE` (auto-on when not
      `DEBUG`) and the `__Host-` cookie name prefix — both require HTTPS. *(Changing
      a cookie name logs everyone out once on that deploy.)*
- [ ] HSTS (1 year, subdomains, preload) and `SECURE_SSL_REDIRECT` — on in `prod.py`.
- [ ] **CSP** is a nonce-based `script-src 'strict-dynamic'` policy, **enforced** by
      default; use `CSP_REPORT_ONLY=True` (+ optional `CSP_REPORT_URI`) only to
      diagnose a new violation.
- [ ] `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and a restrictive
      `Permissions-Policy` are emitted automatically.
- [ ] `TRUSTED_PROXY_COUNT` matches your proxy depth (§2).
- [ ] Secrets are mounted as **files** (`PUB_REPO_SSH_KEY_PATH`,
      `GITHUB_APP_PRIVATE_KEY_PATH`) rather than inline where possible. All
      user/CI-supplied strings are funnelled through `redact_secrets`, so tokens and
      keys never reach logs, audit metadata, task errors, or notifications
      ([INV-SECRET-1], [INV-AUDIT-2]).
- [ ] **`/metrics` is reachable only from your monitoring network** — it is
      intentionally unauthenticated at the app layer; gate it with network policy or
      a private port, never the public ingress.
- [ ] `RATELIMIT_ENABLE=True` and `STEP_UP_REQUIRED=True` in prod.
- [ ] Account **ban** (`is_active=False`, from the Admin Console) is the one
      app-side override of IdP authority — it drops a live session immediately
      ([INV-AUTH-8]); everything else propagates at next login.

---

## Related pages

- [configuration.md](./configuration.md) — the variables referenced here.
- [observability.md](./observability.md) — metrics, dashboards, alerts, Sentry.
- [maintenance.md](./maintenance.md) — backups, upgrades, maintenance mode.
