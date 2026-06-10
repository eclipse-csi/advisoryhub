#!/usr/bin/env bash
# Verify the release version is consistent everywhere it is recorded:
#   - pyproject.toml                 [project] version
#   - uv.lock                        root package version (goes stale unless
#                                    `uv lock` ran after a pyproject bump —
#                                    and then `uv sync --locked` fails everywhere)
#   - charts/advisoryhub/Chart.yaml  version + appVersion (lockstep with the app)
#
# Usage: dev/check_release_versions.sh [vX.Y.Z]
#   With an argument (release.yml passes "$GITHUB_REF_NAME"), the tag must
#   match too. Run by `mise run release-check`, dev/release.sh and the gate
#   step of .github/workflows/release.yml.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# System python3 + stdlib only — same rationale as check_template_comments.py:
# never re-syncs / strips the uv dev environment.
pyproject_version=$(python3 -c '
import tomllib
with open("pyproject.toml", "rb") as f:
    print(tomllib.load(f)["project"]["version"])
')
lock_version=$(python3 -c '
import tomllib
with open("uv.lock", "rb") as f:
    lock = tomllib.load(f)
print(next(p["version"] for p in lock["package"] if p["name"] == "advisoryhub"))
')
# Chart.yaml is repo-controlled, single-document, flat keys — sed is enough.
chart_version=$(sed -n 's/^version: //p' charts/advisoryhub/Chart.yaml)
chart_app_version=$(sed -n 's/^appVersion: "\(.*\)"$/\1/p' charts/advisoryhub/Chart.yaml)

check() {
  local label="$1" actual="$2"
  if [ "$actual" != "$pyproject_version" ]; then
    echo "ERROR: $label is '$actual' but pyproject.toml says '$pyproject_version'" >&2
    fail=1
  else
    echo "OK: $label = $actual"
  fi
}

echo "OK: pyproject.toml [project] version = $pyproject_version"
check "uv.lock root package version (run 'uv lock' after a bump)" "$lock_version"
check "Chart.yaml version" "$chart_version"
check "Chart.yaml appVersion" "$chart_app_version"

if [ "${1:-}" != "" ]; then
  check "tag $1" "${1#v}"
fi

exit "$fail"
