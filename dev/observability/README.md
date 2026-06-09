# Observability dev bundle (Prometheus + Grafana)

This directory wires an opt-in **Prometheus + Grafana** stack into the
AdvisoryHub `docker-compose.yml` so you can see the app's metrics, dashboards,
and alert rules locally. It is **dev/demo only** — production scrapes the app's
`/metrics` with the operator's own Prometheus and ships these dashboards/rules
into the operator's own Grafana.

Both services are gated behind the `observability` compose profile, so the plain
`docker compose up` / `mise run up` stack stays lean and nobody is forced to run
them.

## Run it

```sh
docker compose up                                          # the app + worker + beat
docker compose --profile observability up prometheus grafana   # …plus this stack
# or: mise run obs-up
```

To reach the UIs from your host, publish the ports (run on the host):

```sh
sbx ports <sandbox-name> --publish 9090:9090/tcp   # Prometheus
sbx ports <sandbox-name> --publish 3000:3000/tcp   # Grafana
```

- **Prometheus** → <http://localhost:9090> (try `/targets` and `/alerts`)
- **Grafana** → <http://localhost:3000> — anonymous **Viewer** access is enabled
  for demos; log in as `admin` / `admin` to edit. The Prometheus datasource and
  both dashboards are auto-provisioned.

## What gets scraped

| Target            | Source                          | Series                                            |
| ----------------- | ------------------------------- | ------------------------------------------------- |
| `web:8000`        | django-prometheus middleware    | HTTP requests/responses/latency, DB, cache        |
| `worker:9808`     | `common.celery_metrics` exporter | `advisoryhub_publication_*`, `advisoryhub_celery_task_*`, `advisoryhub_backlog` |
| `localhost:9090`  | Prometheus itself               | scrape health                                     |

The publication, Celery-task, and backlog series live on the **worker** target,
not on `web`'s `/metrics` (they're produced in the worker process). The
`advisoryhub_backlog` gauge is refreshed every 60s by the `backlog-gauge-refresh`
beat task — make sure the `beat` service is running for it to populate.

## Files

```
dev/observability/
├── prometheus.yml                      # scrape jobs + rule_files
├── rules/advisoryhub.rules.yml         # example alert rules (tune to your SLOs)
└── grafana/
    ├── provisioning/
    │   ├── datasources/prometheus.yml  # auto-wire the Prometheus datasource
    │   └── dashboards/dashboards.yml   # file-based dashboard provider
    └── dashboards/
        ├── advisoryhub-overview.json   # request rate / errors / latency
        └── advisoryhub-pipeline.json   # publication + celery + backlog
```

## Not for production

The `admin/admin` Grafana credential, anonymous Viewer access, and the 7-day
Prometheus retention are dev fixtures. Prod runs `gunicorn` with
`PROMETHEUS_MULTIPROC_DIR` set (so `/metrics` aggregates across workers — see
`gunicorn.conf.py` and `config/settings/prod.py`) and is scraped by the
operator's own monitoring. SLO targets and the alerting story are documented in
`docs/specification/architecture.md` §8.8.
