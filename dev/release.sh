#!/usr/bin/env bash
# Cut a release: bump every recorded version in lockstep, then create the
# signed release commit and signed tag. The push stays manual — review first,
# then run the printed command; pushing the tag triggers release-image.yml
# (container image) and release.yml (chart + GitHub release). Full runbook:
# docs/releasing.md.
#
# Usage: dev/release.sh X.Y.Z      (or: mise run release -- X.Y.Z)
set -euo pipefail
cd "$(dirname "$0")/.."

V="${1:-}"
if ! [[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: dev/release.sh X.Y.Z (plain semver; got '${V}')" >&2
  exit 1
fi

# Untracked files don't block (TODO.md stays deliberately untracked) — only
# uncommitted changes to tracked files do.
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "ERROR: working tree has uncommitted changes — commit or stash first" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/v$V" >/dev/null; then
  echo "ERROR: tag v$V already exists" >&2
  exit 1
fi
branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$branch" != "main" ]; then
  echo "WARNING: releasing from '$branch', not 'main'" >&2
fi

# pyproject.toml + uv.lock in one atomic move — no stale-lock window where
# `uv sync --locked` would start failing.
uv version --no-sync "$V"

# Chart version and appVersion track the app version in lockstep (single-app
# repo; image.tag defaults to appVersion).
python3 - "$V" <<'PY'
import re
import sys

v = sys.argv[1]
path = "charts/advisoryhub/Chart.yaml"
with open(path) as f:
    src = f.read()
src, n_version = re.subn(r"(?m)^version: .*$", f"version: {v}", src, count=1)
src, n_app = re.subn(r"(?m)^appVersion: .*$", f'appVersion: "{v}"', src, count=1)
assert n_version == 1 and n_app == 1, "Chart.yaml version/appVersion lines not found"
with open(path, "w") as f:
    f.write(src)
PY

# The OpenAPI contract's info.version tracks the app version in lockstep
# (api/tests/test_openapi_spec.py asserts it equals the installed package
# version, so a stale spec version would fail CI on the release commit).
python3 - "$V" <<'PY'
import re
import sys

v = sys.argv[1]
path = "docs/specification/openapi.yaml"
with open(path) as f:
    src = f.read()
src, n = re.subn(
    r"(?ms)^(info:.*?^  version): .*?$", rf"\g<1>: {v}", src, count=1
)
assert n == 1, "openapi.yaml info.version line not found"
with open(path, "w") as f:
    f.write(src)
PY

# Sanity: the bumped lock still syncs, and every recorded version agrees.
uv sync --locked --extra dev
bash dev/check_release_versions.sh "v$V"

echo
echo "Release notes preview (git-cliff):"
echo "----------------------------------------------------------------------"
git-cliff --unreleased --tag "v$V" --strip header
echo "----------------------------------------------------------------------"

git add pyproject.toml uv.lock charts/advisoryhub/Chart.yaml docs/specification/openapi.yaml
if git diff --cached --quiet; then
  echo "No version changes to commit (already at $V) — tagging HEAD."
else
  # Commit policy (CLAUDE.md): every commit signed and signed-off.
  git commit -S -s -m "chore(release): v$V"
fi
git tag -s "v$V" -m "advisoryhub v$V"

echo
echo "Done. Review the commit and tag, then publish with:"
echo "  git push origin main v$V"
