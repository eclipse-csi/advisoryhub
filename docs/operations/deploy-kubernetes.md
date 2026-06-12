# Deploying on OKD / Kubernetes (Helm)

The repository ships a production Helm chart at
[`charts/advisoryhub/`](../../charts/advisoryhub/). It deploys the three
application processes — web (gunicorn), Celery worker, Celery beat — from the
single published image, plus the migration hook, exposure, probes, and the
optional observability wiring. **It deploys no backing services**: PostgreSQL,
Valkey, the OIDC provider, SMTP and the publication Git repository are
external prerequisites (see the
[operations README §2](./README.md#2-prerequisites)).

The chart targets **OKD/OpenShift first** (`restricted-v2` SCC compatible,
Route exposure) and runs unchanged on **vanilla Kubernetes** (Ingress
exposure, explicit UID/fsGroup). The chart's own
[README](../../charts/advisoryhub/README.md) documents every value; this page
is the end-to-end walkthrough.

---

## 1. Before you start

You need, reachable **from inside the cluster**:

- PostgreSQL (capture a `DATABASE_URL`);
- Valkey/Redis with `--maxmemory-policy noeviction` (three logical DBs:
  broker `/0`, results `/1`, cache `/2`);
- an OIDC confidential client (id + secret, and the four OP endpoints);
- an SMTP relay;
- the publication repo's SSH deploy key (or an HTTPS token);
- a pull secret for `ghcr.io` if the image is private.

---

## 2. Create the Secrets

The chart consumes two Secrets you manage (their names go into
`secrets.existingSecret` and `secrets.files.existingSecret`). Nothing secret
ever passes through Helm values on this path.

```sh
oc new-project advisoryhub   # OKD; `kubectl create namespace advisoryhub` elsewhere

# 1. Environment secret — every key becomes an env var (envFrom).
kubectl -n advisoryhub create secret generic advisoryhub-env \
  --from-literal=DJANGO_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(64))')" \
  --from-literal=DATABASE_URL='postgres://advisoryhub:…@postgres.example.org:5432/advisoryhub' \
  --from-literal=CELERY_BROKER_URL='rediss://:…@valkey.example.org:6379/0' \
  --from-literal=CELERY_RESULT_BACKEND='rediss://:…@valkey.example.org:6379/1' \
  --from-literal=CACHE_URL='rediss://:…@valkey.example.org:6379/2' \
  --from-literal=OIDC_RP_CLIENT_ID='advisoryhub' \
  --from-literal=OIDC_RP_CLIENT_SECRET='…' \
  --from-literal=EMAIL_HOST_USER='…' \
  --from-literal=EMAIL_HOST_PASSWORD='…'
  # optional extras: PUB_REPO_TOKEN, GITHUB_APP_WEBHOOK_SECRET,
  # ECLIPSE_API_CLIENT_ID/_SECRET, SENTRY_DSN, HCAPTCHA_SITE_KEY/_SECRET_KEY,
  # PMI_API_TOKEN, SIMILARITY_LLM_API_KEY

# 2. Key-files secret — mounted as files at /etc/advisoryhub/keys.
kubectl -n advisoryhub create secret generic advisoryhub-keys \
  --from-file=pub-repo-ssh-key=./advisoryhub-deploy-key \
  # --from-file=github-app-private-key=./github-app.pem   # only with ghsa.enabled

# 3. Image pull secret (private ghcr.io image).
kubectl -n advisoryhub create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<user> --docker-password=<PAT>
```

Any env var from [configuration.md](./configuration.md) can be added to the
env Secret — Secret keys override nothing in the chart's ConfigMap (they are
disjoint by design), and per-pod `extraEnv` values win over both.

Optional features follow the same split: e.g. LLM duplicate detection is
toggled by the chart's `similarity.*` values block (`enabled` / `provider` /
`model` / `baseUrl` — see
[integrations.md §5](./integrations.md#5-similarity-llm-provider-optional)),
while its `SIMILARITY_LLM_API_KEY` belongs in the env Secret, never in values.

---

## 3. Install on OKD

`values-okd.yaml`:

```yaml
route:
  enabled: true
  host: advisoryhub.apps.<cluster-domain>

secrets:
  existingSecret: advisoryhub-env
  files:
    existingSecret: advisoryhub-keys

imagePullSecrets:
  - name: ghcr-pull

oidc:
  authorizationEndpoint: https://idp.example.org/…/authorize
  tokenEndpoint: https://idp.example.org/…/token
  userEndpoint: https://idp.example.org/…/userinfo
  jwksEndpoint: https://idp.example.org/…/jwks

email:
  host: smtp.example.org

pubRepo:
  url: git@github.com:example/advisories.git
  cveAssignerOrgId: <EF CNA org UUID>
  knownHosts: |            # optional but recommended: ssh-keyscan github.com
    github.com ssh-ed25519 AAAA…
```

```sh
helm install advisoryhub charts/advisoryhub -n advisoryhub -f values-okd.yaml
```

Notes for OKD:

- Leave `podSecurityContext.runAsUser/runAsGroup/fsGroup` at their `null`
  defaults — the `restricted-v2` SCC assigns them; the image runs as any
  non-root UID in group 0.
- The Route uses **edge TLS** with `insecureEdgeTerminationPolicy: Redirect`
  and the router's default certificate (set `route.tls.certificate`/`key` for
  a custom one). The chart sets `USE_X_FORWARDED_PROTO=True`,
  `TRUSTED_PROXY_COUNT=1`, and derives `DJANGO_ALLOWED_HOSTS` /
  `CSRF_TRUSTED_ORIGINS` / `ADVISORYHUB_BASE_URL` from `route.host` — keep
  them coupled or POSTs will start failing CSRF with opaque 403s.
- A second Route pins the public `/metrics` path to an endpoint-less Service
  (503) — the in-cluster scrape targets are unaffected
  (`exposure.blockMetrics`).

## 4. Install on vanilla Kubernetes

Differences from §3 (full example in
[`charts/advisoryhub/ci/vanilla-values.yaml`](../../charts/advisoryhub/ci/vanilla-values.yaml)):

```yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: advisoryhub.example.org
      paths: [{ path: /, pathType: Prefix }]
  tls:
    - secretName: advisoryhub-tls
      hosts: [advisoryhub.example.org]

podSecurityContext:        # no SCC to assign these — set them explicitly
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 0
  fsGroup: 0               # makes the key-files Secret group-readable
  seccompProfile: { type: RuntimeDefault }
```

TLS-redirect at the edge is the ingress controller's job; the app's
`SECURE_SSL_REDIRECT` is the backstop.

---

## 5. What an install/upgrade does

1. **pre-install/pre-upgrade hook**: a Job runs
   `python manage.py migrate --noinput` (and, when `secrets.create` is used,
   the chart-managed Secret is hook-created first). Old pods keep serving
   while migrations run, so **migrations must stay backward-compatible one
   release back**; destructive schema changes need a two-release dance.
2. Deployments roll: web (RollingUpdate, `maxUnavailable: 0`), worker
   (RollingUpdate, 120 s warm shutdown for in-flight publications), beat
   (singleton, Recreate).
3. `helm test advisoryhub -n advisoryhub` curls `/healthz` through the web
   Service.

Verify:

```sh
kubectl -n advisoryhub logs job/advisoryhub-migrate
kubectl -n advisoryhub get deploy,po -l app.kubernetes.io/instance=advisoryhub
curl -fsS https://advisoryhub.apps.<cluster-domain>/healthz
```

First-run only: complete the
[production bootstrap](./installation.md#2-production-first-run-bootstrap) —
register the OIDC redirect URI (`https://<host>/oidc/callback/`), create the
admin group in the IdP, log in, create projects.

---

## 6. Probes, scaling, disruption

- **web** — liveness `GET /healthz`, readiness `GET /readyz` (DB + cache +
  broker by default: `readyz.includeBroker=true` matches the repo's
  recommendation but couples web readiness to Valkey — flip it if you'd
  rather degrade than drop out of rotation), startup probe with a 150 s
  budget. All probes send an explicit `Host:` header (kubelet probes use the
  pod IP, which `ALLOWED_HOSTS` would reject). Scale via `web.replicaCount`
  or `web.autoscaling`; a PDB keeps 1 available.
- **worker** — TCP probe on the metrics port; scale via
  `worker.replicaCount`/`autoscaling` (CPU is a weak proxy for queue depth —
  consider KEDA). `worker.tmpSizeLimit` (default 1Gi) bounds the emptyDir the
  publication clones land in.
- **beat** — exactly one replica, by template (not values). Don't fight it:
  two beats double-fire every periodic task.

## 7. Monitoring

With the prometheus-operator CRDs installed (kube-prometheus-stack, or OKD
user-workload monitoring):

```yaml
metrics:
  serviceMonitor:
    enabled: true
    labels: { release: kube-prometheus-stack }   # whatever your Prometheus selects on
  prometheusRule:
    enabled: true
  grafanaDashboards:
    enabled: true
    datasourceUid: prometheus
```

The ServiceMonitors pin the Prometheus `job` label to `advisoryhub-web` /
`advisoryhub-worker` — the bundled alert rules and dashboards (byte-copies of
[`dev/observability/`](../../dev/observability/), sync-guarded in CI) select
on those names. On OKD, enable
[user-workload monitoring](https://docs.okd.io/latest/observability/monitoring/enabling-monitoring-for-user-defined-projects.html)
and drop the `labels`.

`networkPolicy.enabled=true` adds ingress-only policies (router → web :8000,
monitoring → metrics, beat fully closed). Egress stays open by default —
restrict it with `networkPolicy.egress` to the endpoints the deployment
actually uses: PostgreSQL, Valkey, the OIDC provider, the SMTP relay, the
publication Git remote, plus — when the optional features are enabled — the
GitHub API (GHSA), the Eclipse API (roster sync), and the LLM provider
(similarity; worker egress).

## 8. Chart development

```sh
mise run helm-lint            # helm lint, default + all ci/ fixtures
mise run helm-template        # render the okd fixture
mise run helm-validate        # render + kubeconform (Route schema vendored
                              #   in dev/kubeconform-schemas/); -- -i offline
mise run verify-chart-assets  # chart copies of rules/dashboards match dev/observability/
```

CI runs the same tasks (`helm` job in `.github/workflows/ci.yml`).
