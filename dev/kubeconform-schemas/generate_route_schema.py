"""Regenerate route_v1.json from OpenShift's published Route CRD.

The Route API is native to OpenShift (absent from the datreeio CRDs-catalog
kubeconform pulls its other CRD schemas from), so its schema is vendored here
for dev/validate_chart.sh. Regenerate after an OpenShift API bump with:

    curl -fsSL -o /tmp/route.crd.yaml \
        https://raw.githubusercontent.com/openshift/microshift/main/assets/crd/route.crd.yaml
    uv run --with pyyaml python dev/kubeconform-schemas/generate_route_schema.py /tmp/route.crd.yaml
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml


def clean(node):
    """openapi2jsonschema-style normalisation.

    - drop null-valued keywords (the published CRD ships ``anyOf: null``, an
      OpenShift featuregate-merge artifact that JSON-Schema compilers reject)
    - resolve ``x-kubernetes-int-or-string`` into a string|integer oneOf
    - drop the remaining ``x-kubernetes-*`` extension keywords
    """
    if isinstance(node, dict):
        for key in [k for k, v in node.items() if v is None]:
            node.pop(key)
        if node.pop("x-kubernetes-int-or-string", None):
            node.pop("type", None)
            node["oneOf"] = [{"type": "string"}, {"type": "integer"}]
        for key in [k for k in node if k.startswith("x-kubernetes-")]:
            node.pop(key)
        for value in node.values():
            clean(value)
    elif isinstance(node, list):
        for value in node:
            clean(value)


def main() -> None:
    crd_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/route.crd.yaml"
    crd = yaml.safe_load(Path(crd_path).read_text())
    v1 = next(v for v in crd["spec"]["versions"] if v["name"] == "v1")
    schema = v1["schema"]["openAPIV3Schema"]
    clean(schema)
    schema["$schema"] = "http://json-schema.org/schema#"

    out = Path(__file__).parent / "route.openshift.io" / "route_v1.json"
    out.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
