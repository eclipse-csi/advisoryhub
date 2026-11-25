# syntax=docker/dockerfile:1
#
# Two build targets from one file:
#   dev        — docker-compose target (deps only; source is bind-mounted)
#   production — the deployable image (last stage, so a bare `docker build .`
#                yields prod): source + baked static files, gunicorn CMD,
#                OpenShift/OKD arbitrary-UID compatible.
#
# Every stage bases on Docker Hardened Images (dhi.io — pulls need a
# one-time `docker login dhi.io`, free Docker account), so even
# `docker compose up` requires that login once. The deployed stage is the
# DHI *runtime* variant — no shell, no package manager — and contains
# zero RUN instructions: everything it needs (venv, app, git/ssh) is COPY'd
# from earlier stages.

# Base images are pinned ONLY on the literal `FROM image:tag@sha256:… AS name`
# lines below; every other stage builds `FROM <that alias>`. Never move a pin
# into an `ARG` + `FROM ${…}`: Dependabot's Dockerfile parser reads literal
# FROM lines only, so an ARG-held image silently drops out of its updates
# (it did, 2026-06 → 2026-11, freezing the DHI base until the Trivy gate
# failed). dev/check_dockerfile_bases.py enforces both rules in this comment
# block (prek + CI).
#
# Digests pin the multi-arch *index* (amd64 CI + arm64 local), not a platform
# manifest; re-resolve with dhi.io credentials:
#   docker buildx imagetools inspect dhi.io/python:<tag>

# uv as a static binary copied from its (digest-pinned) distroless image —
# no pip bootstrap, identical mechanism in every stage.
FROM ghcr.io/astral-sh/uv:0.11.19@sha256:b46b03ddfcfbf8f547af7e9eaefdf8a39c8cebcba7c98858d3162bd28cf536f6 AS uv-dist

# DHI "dev" variant (hardened Debian 13 + bash/apt, runs as root): base of
# the compose dev stage and of every build stage — uv sync, collectstatic,
# and the runtime-deps harvest all need a shell. Nothing from it ships in
# the deployed image except files explicitly COPY'd into `production`.
# The Python patch in the tag MUST equal .python-version (guarded): a
# Dependabot tag bump fails CI until .python-version (and, if its CPython
# list lags, mise's uv pin) is bumped on the same PR.
FROM dhi.io/python:3.14.10-debian13-dev@sha256:331fffd6ff7fcf9bf5f7dbde8d48fad634375baa739d1db23f65e0ec83bcd198 AS dhi-dev

# DHI runtime variant: what actually deploys. git/ssh/libnss_wrapper come
# from the runtime-deps stage (same Debian 13 release line, so any
# overwritten library is byte-identical). Same Python-patch rule as above.
FROM dhi.io/python:3.14.10-debian13@sha256:d20d953b545c83acd9e1b6b6b6d27cf14de38e6a39689334f71454c33cf41893 AS dhi-runtime

# ---------------------------------------------------------------------------
# dev — used by docker-compose (build target: dev)
# ---------------------------------------------------------------------------
FROM dhi-dev AS dev

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    # Use the interpreter bundled in this image; never download a managed one.
    UV_PYTHON_DOWNLOADS=never \
    # Keep the project venv OUTSIDE /app. docker-compose bind-mounts the source
    # at .:/app at runtime, which would shadow an in-project .venv (and a
    # host-built .venv of the wrong arch/python would break imports).
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

# git + ssh: publication pushes (publication/git_service.py shells out to
# them); curl: convenience. DHI apt repos are GPG-signed dhi.io mirrors —
# no https source rewrite needed (that was a python:slim-ism).
# No build-essential/libpq-dev: uv.lock resolves to wheels only (psycopg-binary
# bundles libpq) — if a future dependency ships sdist-only, uv sync fails
# loudly here and the toolchain can be re-added.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-client curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=uv-dist /uv /usr/local/bin/uv

WORKDIR /app

# advisoryhub is a uv *virtual* project (deps-only, no build step), so only the
# lockfile and pyproject are needed to install dependencies — the app source is
# bind-mounted at runtime. Copying just these two files also means a dependency
# edit is the only thing that busts this layer's cache. --locked installs the
# resolved lock exactly and fails if it has drifted from pyproject.toml.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --extra dev --no-install-project --python 3.14

EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

# ---------------------------------------------------------------------------
# prod-base — shared build base for the production stages
# ---------------------------------------------------------------------------
FROM dhi-dev AS prod-base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

COPY --from=uv-dist /uv /usr/local/bin/uv

WORKDIR /app

# ---------------------------------------------------------------------------
# prod-deps — runtime dependencies only (no dev extra)
# ---------------------------------------------------------------------------
FROM prod-base AS prod-deps

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-install-project --python 3.14

# ---------------------------------------------------------------------------
# prod-app — source + baked assets, prepared for the arbitrary-UID runtime
# ---------------------------------------------------------------------------
FROM prod-deps AS prod-app

COPY . /app

# COPY preserves build-context file modes; normalize so an arbitrary runtime
# UID can read the app (root-owned, world-readable, never writable).
RUN chmod -R u=rwX,go=rX /app

# Bake hashed + precompressed static assets (WhiteNoise manifest storage).
# Every env() in config/settings/base.py has a default and collectstatic never
# touches the DB, so a dummy SECRET_KEY is all the build needs. compileall
# pre-compiles app bytecode (the venv's is compiled by UV_COMPILE_BYTECODE);
# at runtime nothing writes .pyc (PYTHONDONTWRITEBYTECODE).
RUN DJANGO_SETTINGS_MODULE=config.settings.prod \
    DJANGO_SECRET_KEY=build-only-collectstatic-dummy \
    python manage.py collectstatic --noinput \
 && python -m compileall -q /app

# HOME for the runtime image. OpenShift restricted-v2 runs the container as
# a random UID in group 0, so it must be group-0 writable: ssh writes
# ~/.ssh/known_hosts there under StrictHostKeyChecking=accept-new. (The UID
# itself is registered at startup by docker/entrypoint.py via nss_wrapper —
# /etc/passwd is never modified.)
RUN mkdir -p /home/advisoryhub/.ssh \
 && chgrp -R 0 /home/advisoryhub && chmod -R g=u /home/advisoryhub

# ---------------------------------------------------------------------------
# runtime-deps — harvest git/ssh/nss_wrapper for the shell-less final stage
# ---------------------------------------------------------------------------
FROM dhi-dev AS runtime-deps

# git + ssh are runtime requirements (publication pushes shell out to them);
# libnss-wrapper backs the arbitrary-UID registration in docker/entrypoint.py.
# `apt-get upgrade` first: `install` leaves dependencies the DHI dev base
# already ships (e.g. krb5, pulled in by openssh-client and libcurl) at the
# base's version, so a Debian security fix published after the DHI build
# (krb5 DSA-6650-1, 2026-11) would otherwise be staged unpatched and fail the
# Trivy gate until DHI rebuilds the tag. Non-interactive with --force-confold:
# DHI ships its own conffiles (e.g. base-files' /etc/debian_version), and the
# dpkg conffile prompt would abort a build with no stdin. Keeping them is
# harmless — only the packages below and their library closure are staged.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
      -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
 && apt-get install -y --no-install-recommends git openssh-client libnss-wrapper \
 && rm -rf /var/lib/apt/lists/*

# Copy the installed payloads + their shared-library closure + dpkg scanner
# metadata into /staging, which the production stage COPYs onto /.
COPY docker/collect-runtime-deps.sh /tmp/collect-runtime-deps.sh
RUN bash /tmp/collect-runtime-deps.sh /staging

# ---------------------------------------------------------------------------
# production — the deployable image (default target; zero RUN instructions)
# ---------------------------------------------------------------------------
FROM dhi-runtime AS production

# revision/version/created are stamped by CI (docker/metadata-action).
LABEL org.opencontainers.image.title="AdvisoryHub" \
      org.opencontainers.image.description="Security advisory authoring, review and publication for Eclipse Foundation projects" \
      org.opencontainers.image.source="https://github.com/eclipse-csi/advisoryhub" \
      org.opencontainers.image.vendor="Eclipse Foundation" \
      org.opencontainers.image.licenses="EPL-2.0"

# git/ssh/libnss_wrapper, their library closure, and /var/lib/dpkg/status.d
# stanzas so scanners keep seeing the staged packages.
COPY --from=runtime-deps /staging/ /
COPY --from=prod-deps /opt/venv /opt/venv
COPY --from=prod-app /app /app
COPY --from=prod-app /home/advisoryhub /home/advisoryhub

# config/celery.py defaults DJANGO_SETTINGS_MODULE to the *dev* settings; bake
# prod so web, worker and beat are all correct without per-process wiring.
# No UV_* here — uv exists only in the build stages.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=config.settings.prod \
    HOME=/home/advisoryhub

WORKDIR /app

# Non-root marker (satisfies runAsNonRoot admission); OpenShift replaces it
# with a namespace-range UID — nothing may assume 1001 specifically.
USER 1001

EXPOSE 8000
# Exec form end to end — the image has no shell. `python` resolves through
# PATH to /opt/venv/bin/python; the entrypoint registers the runtime UID
# (nss_wrapper) and then execs the command, keeping it PID 1. The script is
# referenced from the /app source COPY (correct world-readable modes from
# the chmod above) — a dedicated COPY into /usr/local/bin would *create*
# that directory on this base, which doesn't ship it, with the file's own
# --chmod mode and no traverse bit for non-root users.
ENTRYPOINT ["python", "/app/docker/entrypoint.py"]
# Web entrypoint. gunicorn sizes workers from the WEB_CONCURRENCY env var
# (defaults to 1); worker/beat deployments override this CMD with the celery
# command lines documented in docs/operations/running-in-production.md.
CMD ["gunicorn", "config.wsgi", "-c", "gunicorn.conf.py", "--bind", "0.0.0.0:8000"]
