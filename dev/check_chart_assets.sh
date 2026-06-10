#!/usr/bin/env bash
# Verify the Helm chart's embedded observability assets are byte-identical to
# their sources in dev/observability/ (Helm cannot .Files.Get outside the
# chart directory, so they are copied — this guard keeps the copies honest).
# Run by prek (pre-commit stage) and CI's helm job.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

check() {
  local src="$1" copy="$2"
  if cmp -s "$src" "$copy"; then
    echo "OK: $copy matches $src"
  else
    echo "ERROR: $copy has drifted from $src" >&2
    echo "  Re-sync with: cp $src $copy" >&2
    fail=1
  fi
}

check dev/observability/rules/advisoryhub.rules.yml \
  charts/advisoryhub/files/prometheus-rules.yaml
check dev/observability/grafana/dashboards/advisoryhub-overview.json \
  charts/advisoryhub/files/dashboards/advisoryhub-overview.json
check dev/observability/grafana/dashboards/advisoryhub-pipeline.json \
  charts/advisoryhub/files/dashboards/advisoryhub-pipeline.json

exit "$fail"
