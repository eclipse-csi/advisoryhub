#!/usr/bin/env bash
# Render the Helm chart for each ci/ fixture and validate the manifests with
# kubeconform. ServiceMonitor / PrometheusRule schemas come from the datreeio
# CRDs-catalog; Route (a native OpenShift API, absent from that catalog) is
# validated against a vendored schema generated from openshift/api's CRD
# (dev/kubeconform-schemas/). Pass -i (or set OFFLINE=1) to skip the remote
# catalog when it is unreachable.
# Run by CI's helm job and `mise run helm-validate`.
set -euo pipefail
cd "$(dirname "$0")/.."

CHART=charts/advisoryhub
CRD_SCHEMAS='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
LOCAL_SCHEMAS='dev/kubeconform-schemas/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'

args=(-strict -summary -schema-location default -schema-location "$LOCAL_SCHEMAS")
if [ "${OFFLINE:-0}" = "1" ] || [ "${1:-}" = "-i" ]; then
  args+=(-ignore-missing-schemas)
else
  args+=(-schema-location "$CRD_SCHEMAS")
fi

for fixture in minimal okd vanilla; do
  echo "=== kubeconform: ci/${fixture}-values.yaml ==="
  helm template advisoryhub "$CHART" -f "$CHART/ci/${fixture}-values.yaml" \
    | kubeconform "${args[@]}"
done
