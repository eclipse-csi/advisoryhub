# AdvisoryHub Helm chart

Deploys AdvisoryHub — web (gunicorn), Celery worker, Celery beat — from the
single image published at `ghcr.io/mbarbero/advisoryhub`, plus a migration
hook Job, Route/Ingress exposure, probes, PDB/HPA, NetworkPolicies, and
optional prometheus-operator / Grafana wiring.

End-to-end walkthrough (OKD and vanilla Kubernetes):
[`docs/operations/deploy-kubernetes.md`](../../docs/operations/deploy-kubernetes.md).
`values.yaml` is exhaustively commented and is the reference for every knob;
this README covers the contracts that aren't obvious from it.

## Prerequisites (the chart deploys NONE of these)

- **PostgreSQL** — the only stateful store (`DATABASE_URL`).
- **Valkey/Redis** with `--maxmemory-policy noeviction` — broker (`/0`),
  results (`/1`), cache (`/2`).
- **OIDC provider** (confidential client) · **SMTP relay** ·
  **publication Git repository** (SSH deploy key or token).
- Pull secret for ghcr.io if the image is private (`imagePullSecrets`).

## The two-Secret contract

**1. Env Secret** (`secrets.existingSecret`) — applied with `envFrom` to every
container. Keys are plain env-var names from
[`docs/operations/configuration.md`](../../docs/operations/configuration.md):

| Key | Required |
|---|---|
| `DJANGO_SECRET_KEY` | yes |
| `DATABASE_URL` | yes |
| `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, `CACHE_URL` | yes |
| `OIDC_RP_CLIENT_ID`*, `OIDC_RP_CLIENT_SECRET` | yes |
| `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD` | if SMTP needs auth |
| `PUB_REPO_TOKEN` | only with `pubRepo.auth: token` |
| `GITHUB_APP_WEBHOOK_SECRET` | only with `ghsa.enabled` |
| `ECLIPSE_API_CLIENT_ID`, `ECLIPSE_API_CLIENT_SECRET` | only with `rosterSync.enabled` |
| `SENTRY_DSN`, `HCAPTCHA_SITE_KEY`, `HCAPTCHA_SECRET_KEY`, `PMI_API_TOKEN` | optional |

\* `OIDC_RP_CLIENT_ID` may instead live in values (`oidc.clientId`) — it is
config, not secret; pick one place.

**2. Key-files Secret** (`secrets.files.existingSecret`) — mounted read-only
at `/etc/advisoryhub/keys` (mode `0440`; readable through the fsGroup the SCC
assigns) into web and worker. Expected item names:

- `pub-repo-ssh-key` — with `pubRepo.auth: ssh`; the chart points
  `PUB_REPO_SSH_KEY_PATH` at it.
- `github-app-private-key` — with `ghsa.enabled`; the chart points
  `GITHUB_APP_PRIVATE_KEY_PATH` at it.

`secrets.create: true` + `secrets.values` render a chart-managed Secret
instead — dev/eval only (secret material in values files lands in release
history; the Secret is hook-annotated so the migrate Job can use it, and hook
resources survive `helm uninstall`).

Rotating an *existing* Secret does not restart pods (its contents are
invisible to Helm): `kubectl rollout restart deploy -l
app.kubernetes.io/instance=<release>` after rotation, or run a reloader
controller via `podAnnotations`.

## Design decisions you should not fight

- **beat is a hardcoded singleton** (`replicas: 1`, `Recreate`, no values
  knob): two beats double-fire every periodic task.
- **`--pool=threads` on the worker is fixed**: it's what lets one
  per-pod exporter see every task thread's metrics; scale with
  `worker.concurrency` and `worker.replicaCount`.
- **`PROMETHEUS_MULTIPROC_DIR` is set on web only** — putting it on the
  worker corrupts the worker's single-process exporter.
- **Migrations are a `pre-install,pre-upgrade` hook Job** (not an
  initContainer): exactly one run per release operation. Old pods serve while
  it runs ⇒ migrations must be backward-compatible one release back;
  destructive changes need a two-release dance.
- **Public `/metrics` is blackholed** (`exposure.blockMetrics`): the app
  serves `/metrics` unauthenticated on its only port, so the Route/Ingress
  send that path to an endpoint-less Service (503). In-cluster scrapes use
  the Services directly and are unaffected.
- **`DJANGO_ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, `ADVISORYHUB_BASE_URL`
  and the probe `Host:` header all derive from `route.host`/`ingress.hosts`**.
  Override `django.allowedHosts`/`csrfTrustedOrigins` only if you know why —
  decoupling them produces opaque CSRF 403s.

## OKD vs vanilla Kubernetes

| | OKD/OpenShift | Vanilla |
|---|---|---|
| Exposure | `route.enabled` (edge TLS, Redirect) | `ingress.enabled` |
| UID/fsGroup | leave `null` (SCC assigns; image accepts any UID in group 0) | set `runAsUser`/`runAsGroup`/`fsGroup` |
| NetworkPolicy peers | defaults match OVN + SDN router and `openshift-monitoring` | replace `networkPolicy.*Peers` with your controller's namespace selectors |

`containerSecurityContext.readOnlyRootFilesystem: true` is the default and
works: writes go to the `/tmp` emptyDirs (and the web metrics emptyDir), and
the image's entrypoint falls back to nss_wrapper to register the arbitrary
UID when `/etc/passwd` is read-only.

## Observability toggles

`metrics.serviceMonitor` / `metrics.prometheusRule` /
`metrics.grafanaDashboards` (all default-off; need the prometheus-operator
CRDs). The ServiceMonitors pin `job=advisoryhub-web|worker` because the
bundled rules/dashboards (`files/`, byte-copies of `dev/observability/`
guarded by `dev/check_chart_assets.sh`) select on those job names. Dashboard
datasource uid is rewritten to `metrics.grafanaDashboards.datasourceUid`.

## Upgrades & rollback

`helm upgrade` runs migrations first (hook), then rolls deployments
(config/secret checksums on pod templates force a roll when chart-managed
config changes). `helm rollback` rolls pods back but **never un-runs
migrations** — that's the other half of the backward-compatibility contract.

## Chart development

```sh
mise run helm-lint && mise run helm-validate   # lint + kubeconform, all ci/ fixtures
mise run helm-template                          # render the okd fixture
```
