#!/usr/bin/env bash
# pip-audit over the LOCKED dependency set (uv.lock), not the installed venv.
#
# Auditing the lock keeps the result independent of local .venv state: after a
# dependency bump, a not-yet-resynced venv would otherwise fail the audit
# spuriously — or, in the reverse case, pass while the committed lock is
# vulnerable. `--isolated` has uv materialise the locked runtime set (no dev
# extra — the same set CI's security job audits) into an ephemeral env, leaving
# .venv untouched; pip-audit then audits that env. `--locked` also fails if
# uv.lock is stale relative to pyproject.toml.
#
# NOT `uv export | pip-audit -r`: requirements mode (pip-audit >= 2.8) always
# builds a venv via the stdlib venv module, whose ensurepip step SIGABRTs on
# uv-managed CPython on macOS. uv builds the env here instead.
#
# Needs network: uv fetches pip-audit, pip-audit queries the PyPI advisory DB.
# Run by prek (pre-push stage).
set -euo pipefail
cd "$(dirname "$0")/.."

# Any active venv (e.g. mise-activated .venv) is irrelevant to the isolated
# env and would only make uv inspect/warn about it — drop it from the env.
unset VIRTUAL_ENV

# --skip-editable: the project itself is installed editable in the ephemeral
# env (uv run has no --no-install-project); it isn't on PyPI, so skip it.
uv run --isolated --locked --with pip-audit pip-audit --skip-editable
