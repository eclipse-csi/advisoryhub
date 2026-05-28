FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    # Use the interpreter bundled in this image; never download a managed one.
    UV_PYTHON_DOWNLOADS=never \
    # Keep the project venv OUTSIDE /app. docker-compose bind-mounts the source
    # at .:/app at runtime, which would shadow an in-project .venv (and a
    # host-built .venv of the wrong arch/python would break imports).
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential libpq-dev git openssh-client curl \
 && rm -rf /var/lib/apt/lists/*

# uv handles dependency resolution/installation from uv.lock. Install it via
# pip (already present, reachable wherever PyPI is) rather than pulling a
# separate registry image.
RUN pip install --upgrade pip && pip install uv

WORKDIR /app

# advisoryhub is a uv *virtual* project (deps-only, no build step), so only the
# lockfile and pyproject are needed to install dependencies — the app source is
# bind-mounted at runtime. Copying just these two files also means a dependency
# edit is the only thing that busts this layer's cache. --locked installs the
# resolved lock exactly and fails if it has drifted from pyproject.toml.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --extra dev --no-install-project --python 3.12

EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
