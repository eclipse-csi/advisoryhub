# Installation

Two paths: a **local evaluation** stack you can bring up in minutes with
docker-compose, and the **production first-run bootstrap** you follow when wiring
a real deployment. Read [README.md](./README.md) for the prerequisites first.

---

## 1. Local evaluation (docker-compose)

The repository's `docker-compose.yml` and `Dockerfile` are a **self-contained dev
stack** — they bundle PostgreSQL, Valkey, and a Kanidm OIDC provider, and need no
`.env` editing. They are **not** a production deployment (see §3).

```sh
# 0. One time: the app images base on Docker Hardened Images, whose registry
#    refuses anonymous pulls (free Docker account).
docker login dhi.io

# 1. Start the bundled OIDC provider, then bootstrap it (one time).
docker compose up -d kanidm
bash dev/kanidm/setup.sh          # mints the OIDC client secret into dev/kanidm/.env.kanidm

# 2. Bring up the app (web + worker + beat + postgres + valkey).
docker compose up

# 3. In another terminal: apply the schema and seed demo data.
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_demo --with-publish-repo /tmp/advisoryhub-pub.git
```

Sign in at `http://localhost:8000/` as **`alice@example.org`** /
**`correcthorsebatterystaple`** (created by the bootstrap script to match
`seed_demo`). The bootstrap also creates the admin user `eclipse-admin`
(email `admin@example.org`) and the groups `advisoryhub-security`,
`demo-lantern-security`, `demo-marigold-security`.

Reset everything (drops volumes, rebuilds images so a changed `Dockerfile` /
`uv.lock` is picked up):

```sh
docker compose down -v && docker compose build && docker compose up -d kanidm \
  && bash dev/kanidm/setup.sh && docker compose up
```

Optional add-ons:

- **Observability stack** (Prometheus + Grafana), gated behind a compose profile:
  `docker compose --profile observability up prometheus grafana` — see
  [observability.md](./observability.md).
- **[mise](https://mise.jdx.dev) task wrappers**: `mise run up` / `down` / `build`
  / `reset` / `migrate` / `seed` / `obs-up` wrap the commands above 1:1.

> `seed_demo` is a **development-only** convenience. It is destructive with
> `--reset` and backdates timestamps; never run it against a production database.

---

## 2. Production first-run bootstrap

Production is **platform-agnostic**: you provision the backing services, inject
configuration through your platform's secret manager, and run the three
application processes. The ordered sequence:

### 2.1 Provision backing services

- **PostgreSQL** — create the database and a role; capture the `DATABASE_URL`.
- **Valkey / Redis** — with `--maxmemory-policy noeviction`; in prod prefer
  `rediss://` (TLS) + AUTH. One instance backs all three logical DBs (broker, an
  unused result backend, cache).
- **OIDC provider** — register a confidential client and model the groups; see
  [integrations.md §1](./integrations.md#1-oidc-identity-provider).
- **Publication Git repo** — create it and provision push credentials; see
  [integrations.md §2](./integrations.md#2-publication-git-repository).

### 2.2 Set configuration

Inject the environment variables for your deployment (web, worker, and beat all
read the same configuration). `.env.example` is the annotated reference;
[configuration.md](./configuration.md) is the grouped catalogue. At minimum you
must set `DJANGO_SECRET_KEY`, `DJANGO_ALLOWED_HOSTS`, `DATABASE_URL`,
`CELERY_BROKER_URL`, `CACHE_URL`, the `OIDC_*` block, and (to publish) the
`PUB_REPO_*` block.

### 2.3 Migrate and collect static

```sh
python manage.py migrate
python manage.py collectstatic --noinput
```

Run these against the production settings module (`DJANGO_SETTINGS_MODULE=config.settings.prod`;
`config/wsgi.py` and `config/asgi.py` already default to it). `collectstatic`
produces the content-hashed, compressed assets WhiteNoise serves — see
[running-in-production.md §3](./running-in-production.md#3-static-files).

### 2.4 Establish the admin group

AdvisoryHub never manages group membership itself — it mirrors the OIDC group
claim on every login ([INV-OIDC-1](../specification/invariant.md#inv-oidc-1)). Before anyone can administer the running
instance:

1. In your identity provider, create the **admin group** whose name matches
   `OIDC_ADMIN_GROUP` (default `advisoryhub-security`) and add your initial
   administrators to it.
2. Those users gain Django `is_staff` / `is_superuser` automatically at their
   next login ([INV-OIDC-3](../specification/invariant.md#inv-oidc-3)).

Projects, their security teams, and the **mature-publisher** flag are created and
managed **in-app** afterward (Admin Console at `/admin/`) — not by any bootstrap
script. Mature-publisher status lives on the project row, not in the identity
provider.

### 2.5 Start the processes and verify

Start `web`, `worker`, and `beat` (commands in
[running-in-production.md §1](./running-in-production.md#1-process-topology)),
then verify:

```sh
curl -fsS https://<host>/healthz     # liveness — {"status":"ok"}
curl -fsS https://<host>/readyz      # readiness — 200 only if DB + cache reachable
```

---

## 3. The container image

The repository `Dockerfile` is multi-target:

- **`dev`** (what docker-compose builds): dependencies only, dev extras
  included, `CMD runserver`, source bind-mounted. Never serves real traffic.
- **`production`** (the default target — CI publishes it to
  `ghcr.io/mbarbero/advisoryhub` via `.github/workflows/release-image.yml`,
  scanned, SBOM/provenance-attested, and cosign-signed): runtime dependencies
  only, source and `collectstatic` output baked in, default `CMD` gunicorn.

Production-image facts an operator needs:

- **Base**: the Docker Hardened Images *runtime* variant
  (`dhi.io/python:…-debian13`) — **no shell, no package manager**. Build
  stages use the `-dev` variant; `git`, `ssh`, and `libnss_wrapper` (plus
  their shared-library closure and dpkg scanner metadata) are harvested by
  `docker/collect-runtime-deps.sh` and COPY'd into the final stage, which
  contains zero RUN instructions. The compose `dev` target bases on the
  `-dev` variant too, so every local build — including `docker compose up`
  — needs a one-time `docker login dhi.io` (free Docker account); the
  *published* image on ghcr.io needs no DHI credentials.
- **No shell inside**: `kubectl exec … -- sh` (or `bash`) cannot work.
  Exec `python`, `git`, or `celery` directly, or use `kubectl debug` with
  an ephemeral debug image for filesystem inspection.
- **One image, three processes** — override the command for the task tier:
  - web (default CMD): `gunicorn config.wsgi -c gunicorn.conf.py --bind 0.0.0.0:8000`
    (worker count via the `WEB_CONCURRENCY` env var)
  - worker: `celery -A config worker -l info --pool=threads --concurrency=4`
  - beat: `celery -A config beat -l info --schedule=/tmp/celerybeat-schedule`
- `DJANGO_SETTINGS_MODULE=config.settings.prod` is baked in (override-able).
- **OpenShift-compatible**: runs as any non-root UID in group 0. The
  entrypoint (`docker/entrypoint.py` — plain Python, since the image has
  no shell) registers the runtime UID through nss_wrapper (`/tmp/passwd`
  + `LD_PRELOAD`); `/etc/passwd` is never modified, and the same code
  path covers writable and read-only root filesystems. Writable paths
  needed at runtime: `/tmp`, and on web `PROMETHEUS_MULTIPROC_DIR` —
  mount emptyDirs there when running with `readOnlyRootFilesystem`.
- Optional strict SSH host pinning: mount a pre-populated file at
  `/etc/ssh/ssh_known_hosts` (otherwise publication pushes trust the remote
  on first contact via `StrictHostKeyChecking=accept-new`).

For Kubernetes/OKD, the Helm chart in `charts/advisoryhub/` wires all of this
up — see [deploy-kubernetes.md](./deploy-kubernetes.md).

---

## Related pages

- [configuration.md](./configuration.md) — every environment variable.
- [running-in-production.md](./running-in-production.md) — how to run the processes.
- [deploy-kubernetes.md](./deploy-kubernetes.md) — Helm chart deployment on OKD / Kubernetes.
- [integrations.md](./integrations.md) — OIDC, publication repo, GHSA, roster sync.
