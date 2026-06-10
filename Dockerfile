# syntax=docker/dockerfile:1
#
# Two build targets from one file:
#   dev        — docker-compose target (deps only; source is bind-mounted)
#   production — the deployable image (last stage, so a bare `docker build .`
#                yields prod): source + baked static files, gunicorn CMD,
#                OpenShift/OKD arbitrary-UID compatible.
#
# Production stages base on Docker Hardened Images (dhi.io — requires
# `docker login dhi.io`); the dev stage stays on the public python:slim so
# `docker compose up` needs no registry credentials.

# uv as a static binary copied from its (digest-pinned) distroless image —
# no pip bootstrap, identical mechanism in every stage.
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.19@sha256:b46b03ddfcfbf8f547af7e9eaefdf8a39c8cebcba7c98858d3162bd28cf536f6
# Patch version matches .python-version; bump both together.
ARG DEV_BASE_IMAGE=python:3.14.5-slim@sha256:c845af9399020c7e562969a13689e929074a10fd057acd1b1fad06a2fb068e97
# DHI "dev" variant: hardened Debian 13 + bash/apt (the runtime variant has no
# shell or package manager, and the publication pipeline shells out to
# git/ssh — see publication/git_service.py). Pin a digest here once resolved
# with dhi.io credentials: docker buildx imagetools inspect dhi.io/python:3.14.5-debian13-dev
ARG PROD_BASE_IMAGE=dhi.io/python:3.14.5-debian13-dev@sha256:a787019910f2bcf699178a28903ce40501db4e853ec09453815175ae46922d5e

FROM ${UV_IMAGE} AS uv-dist

# ---------------------------------------------------------------------------
# dev — used by docker-compose (build target: dev)
# ---------------------------------------------------------------------------
FROM ${DEV_BASE_IMAGE} AS dev

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

# git + ssh: publication pushes (GitPython shells out); curl: convenience.
# No build-essential/libpq-dev: uv.lock resolves to wheels only (psycopg-binary
# bundles libpq) — if a future dependency ships sdist-only, uv sync fails
# loudly here and the toolchain can be re-added.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
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
# prod-base — shared hardened base for the production stages
# ---------------------------------------------------------------------------
FROM ${PROD_BASE_IMAGE} AS prod-base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

# git + ssh are runtime requirements (publication pushes); libnss-wrapper backs
# the arbitrary-UID fallback in docker/entrypoint.sh when the root filesystem
# is read-only (OpenShift restricted-v2 + readOnlyRootFilesystem).
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-client libnss-wrapper \
 && rm -rf /var/lib/apt/lists/*

COPY --from=uv-dist /uv /usr/local/bin/uv

WORKDIR /app

# ---------------------------------------------------------------------------
# prod-deps — runtime dependencies only (no dev extra)
# ---------------------------------------------------------------------------
FROM prod-base AS prod-deps

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-install-project --python 3.14

# ---------------------------------------------------------------------------
# production — the deployable image (default target)
# ---------------------------------------------------------------------------
FROM prod-base AS production

# revision/version/created are stamped by CI (docker/metadata-action).
LABEL org.opencontainers.image.title="AdvisoryHub" \
      org.opencontainers.image.description="Security advisory authoring, review and publication for Eclipse Foundation projects" \
      org.opencontainers.image.source="https://github.com/mbarbero/advisoryhub" \
      org.opencontainers.image.vendor="Eclipse Foundation" \
      org.opencontainers.image.licenses="EPL-2.0"

COPY --from=prod-deps /opt/venv /opt/venv
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

COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh

# config/celery.py defaults DJANGO_SETTINGS_MODULE to the *dev* settings; bake
# prod so web, worker and beat are all correct without per-process wiring.
ENV DJANGO_SETTINGS_MODULE=config.settings.prod \
    HOME=/home/advisoryhub

# OpenShift restricted-v2 runs the container as a random UID in group 0:
#  - HOME must be group-0 writable (ssh writes ~/.ssh/known_hosts under
#    StrictHostKeyChecking=accept-new);
#  - /etc/passwd group-writable lets the entrypoint register the runtime UID
#    (ssh refuses to run for a UID with no passwd entry).
RUN mkdir -p /home/advisoryhub/.ssh \
 && chgrp -R 0 /home/advisoryhub && chmod -R g=u /home/advisoryhub \
 && chmod g=u /etc/passwd

# Non-root marker (satisfies runAsNonRoot admission); OpenShift replaces it
# with a namespace-range UID — nothing may assume 1001 specifically.
USER 1001

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# Web entrypoint. gunicorn sizes workers from the WEB_CONCURRENCY env var
# (defaults to 1); worker/beat deployments override this CMD with the celery
# command lines documented in docs/operations/running-in-production.md.
CMD ["gunicorn", "config.wsgi", "-c", "gunicorn.conf.py", "--bind", "0.0.0.0:8000"]
