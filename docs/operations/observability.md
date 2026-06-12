# Observability

Logging, Prometheus metrics, the bundled dashboards/alerts, and Sentry. SLO
targets and the deeper rationale are in
[`../specification/architecture.md`](../specification/architecture.md) §8.

---

## 1. Logging

- **`LOG_FORMAT`** — `json` (production; one JSON object per line, ready for a log
  shipper) or `plain` (human-readable, dev). **`LOG_LEVEL`** sets the root level
  (`INFO` by default).
- Every log record carries the **request id**: `RequestIDMiddleware` reads an
  inbound `X-Request-ID` (or generates one), stamps it on every record for that
  request, and echoes it back in the `X-Request-ID` response header — so you can
  stitch a request together across logs.
- Secrets never reach the logs: all user/CI-supplied strings pass through
  `redact_secrets` ([INV-SECRET-1]).

---

## 2. Metrics

The `/metrics` endpoint (Prometheus text format) is wired **unconditionally** and
is **unauthenticated at the app layer** — keep it on a private port / network, never
the public ingress. Metrics are produced in two places:

| Target | Source | Series |
|---|---|---|
| **web** `/metrics` | `django-prometheus` middleware | `django_http_*` request/response counts and latency histograms, plus DB and cache series. |
| **worker** exporter (`PROMETHEUS_WORKER_METRICS_PORT`) | `common/metrics.py` + `common/celery_metrics.py` | the custom `advisoryhub_*` series below. |

Custom worker series:

- `advisoryhub_publication_total{status}` — `started` / `succeeded` / `failed`.
- `advisoryhub_publication_stage_total{stage}` — per pipeline stage (OSV/CSAF/CVE
  build, git commit, git push).
- `advisoryhub_publication_duration_seconds` — publication duration histogram.
- `advisoryhub_celery_task_total{task,status}` — `success` / `failure` / `retry`.
- `advisoryhub_celery_task_duration_seconds{task}` — task duration histogram.
- `advisoryhub_similarity_check_total{status}` — `started` / `succeeded` / `failed`
  LLM duplicate-detection checks (the task also shows up in the two series above as
  `task="similarity.run_similarity_check"`). Stays flat unless
  `SIMILARITY_CHECK_ENABLED`.
- `advisoryhub_backlog{queue}` — live queue depths (`pub_failed`, `cve_open`,
  `review_open`, `triage`, `triage_routing`, `orphan`, `reassignment`), refreshed
  every 60s by the `backlog-gauge-refresh` beat task — so **`beat` must be running**
  for this gauge to populate.

**Under gunicorn**, set `PROMETHEUS_MULTIPROC_DIR` (a writable, empty-at-boot
tmpfs) and run with `gunicorn config.wsgi -c gunicorn.conf.py`; otherwise the
custom counters report only the worker that served the scrape. Run the Celery
worker with `--pool=threads` so one exporter sees all task threads. Scrape **both**
the web and worker targets.

---

## 3. Bundled dashboards & alerts (a starting template)

`dev/observability/` wires an **opt-in** Prometheus + Grafana stack into
docker-compose (compose profile `observability`). It is **dev/demo only** — in
production you scrape `/metrics` with your own Prometheus and ship these assets
into your own Grafana/Alertmanager — but the configs are a ready template.

```sh
docker compose --profile observability up prometheus grafana   # or: mise run obs-up
```

- **Prometheus** (`dev/observability/prometheus.yml`) scrapes `advisoryhub-web`
  (`web:8000/metrics`), `advisoryhub-celery` (`worker:9808`), and itself; loads
  alert rules from `rules/*.rules.yml`.
- **Grafana** (`localhost:3000`, dev fixture `admin`/`admin`, anonymous Viewer)
  auto-provisions the datasource and two dashboards:
  `advisoryhub-overview` (request rate / errors / latency) and
  `advisoryhub-pipeline` (publication outcomes + Celery throughput + backlog).

**Example alert rules** (`dev/observability/rules/advisoryhub.rules.yml`) — tune the
thresholds to your own SLOs before relying on them:

| Alert | Severity | Fires when |
|---|---|---|
| `AdvisoryHubTargetDown` | critical | a web/worker scrape target is unreachable for 1m. |
| `AdvisoryHubHigh5xxRate` | critical | >2% of responses are 5xx over 5m. |
| `AdvisoryHubLatencySLOBurn` | warning | p95 request latency > 1s for 10m. |
| `AdvisoryHubPublicationFailureRate` | warning | >10% of publication runs fail over 15m. |
| `AdvisoryHubPublicationBacklogStuck` | warning | the failed-publication backlog stays > 5 for 30m. |
| `AdvisoryHubCeleryFailureSpike` | warning | > 0.2 task failures/s over 10m. |
| `AdvisoryHubCeleryStalled` | critical | work is queued but no Celery task progresses for 10m (suspect a down broker). |

The dev stack has no Alertmanager — firing alerts show in Prometheus `/alerts` and
Grafana; wire an Alertmanager in production to actually page. See
`dev/observability/README.md` for the full layout.

On Kubernetes/OKD, the Helm chart ships these same rules and dashboards as a
`PrometheusRule` and Grafana-sidecar ConfigMaps (`metrics.prometheusRule` /
`metrics.grafanaDashboards`), with ServiceMonitors that pin the `job` label to
the names the rules expect — see
[deploy-kubernetes.md §7](./deploy-kubernetes.md#7-monitoring). The chart's
copies are kept byte-identical to `dev/observability/` by
`dev/check_chart_assets.sh` (prek + CI).

---

## 4. Sentry

Error reporting initialises only when `SENTRY_DSN` is set:

- **`SENTRY_DSN`** — the project DSN (a secret); empty disables Sentry entirely.
- **`SENTRY_ENVIRONMENT`** — environment tag (e.g. `production`).
- **`SENTRY_TRACES_SAMPLE_RATE`** — performance-trace sample rate (`0`–`1.0`).

---

## Related pages

- [running-in-production.md](./running-in-production.md) — the worker/beat processes and the multiproc setup.
- [configuration.md](./configuration.md) — the observability variables.
