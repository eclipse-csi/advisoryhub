"""Drift guards: docs/specification/openapi.yaml <-> the Django URLconf.

The spec is hand-written (no DRF/ninja to generate it from), so these tests
keep it honest: the document must validate as OpenAPI 3.0, every /api/ route
must appear in the spec (and vice versa) with exactly the methods the view
declares, the out-of-namespace endpoints it documents must still exist, and
``info.version`` must track the application version (bumped by
dev/release.sh).

No database needed — these only resolve the URLconf and parse YAML.
"""

from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path

import pytest
import yaml

SPEC_PATH = Path(__file__).resolve().parents[2] / "docs" / "specification" / "openapi.yaml"

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
# OpenAPI path-item keys that are not operations.
NON_OPERATION_KEYS = {"parameters", "summary", "description", "servers", "$ref"}

# Documented endpoints that live outside the /api/ URLconf. Spec-side presence
# is asserted here; code-side presence via django.urls.resolve.
OUT_OF_NAMESPACE = [
    ("/ghsa/webhook/", "post"),
    ("/report/projects.json", "get"),
    ("/healthz", "get"),
    ("/readyz", "get"),
]

# <advid:advisory_id> -> {advisory_id}
_CONVERTER = re.compile(r"<(?:[^:>]+:)?([^>]+)>")


@pytest.fixture(scope="module")
def spec() -> dict:
    return yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))


def _urlconf_api_paths() -> dict[str, object]:
    """Map every /api/ route (in OpenAPI path syntax) to its view callback.

    Goes through the root resolver (not ``import api.urls``) so the custom
    ``advid`` path converter is registered first, and so the actual mount
    prefix is used rather than assumed.
    """
    from django.urls import get_resolver

    for resolver in get_resolver().url_patterns:
        if getattr(resolver, "namespace", None) == "api":
            prefix = "/" + str(resolver.pattern)
            return {
                prefix + _CONVERTER.sub(r"{\1}", str(p.pattern)): p.callback
                for p in resolver.url_patterns  # flat list, no nested includes
            }
    raise AssertionError("no 'api'-namespaced include found in ROOT_URLCONF")


def _declared_methods(callback) -> set[str] | None:
    """Recover the ``require_methods_json([...])`` list from a view callback.

    Every decorator in api/ uses functools.wraps, so the ``__wrapped__`` chain
    is walkable; the methods list lives in a closure cell of one wrapper.
    """
    fn, seen = callback, set()
    while fn is not None and id(fn) not in seen:
        seen.add(id(fn))
        for cell in fn.__closure__ or ():
            try:
                value = cell.cell_contents
            except ValueError:  # empty cell
                continue
            if (
                isinstance(value, list)
                and value
                and all(isinstance(m, str) and m in HTTP_METHODS for m in value)
            ):
                return set(value)
        fn = getattr(fn, "__wrapped__", None)
    return None


def test_spec_is_valid_openapi(spec):
    from openapi_spec_validator import validate

    validate(spec)  # raises OpenAPIValidationError on any structural violation


def test_api_paths_match_spec_bidirectionally(spec):
    code_paths = set(_urlconf_api_paths())
    spec_paths = {p for p in spec["paths"] if p.startswith("/api/")}
    assert code_paths == spec_paths, (
        f"URLconf and openapi.yaml disagree on /api/ paths.\n"
        f"  only in URLconf (add to the spec): {sorted(code_paths - spec_paths)}\n"
        f"  only in spec (remove or fix):      {sorted(spec_paths - code_paths)}"
    )


def test_api_methods_match_spec(spec):
    for path, callback in _urlconf_api_paths().items():
        declared = _declared_methods(callback)
        assert declared is not None, (
            f"{path}: could not find a require_methods_json([...]) methods list "
            f"on the view — every /api/ view must declare its methods"
        )
        spec_ops = {key.upper() for key in spec["paths"][path] if key not in NON_OPERATION_KEYS}
        assert spec_ops == declared, (
            f"{path}: spec documents {sorted(spec_ops)} but the view declares {sorted(declared)}"
        )


def test_out_of_namespace_endpoints_present(spec):
    from django.urls import resolve

    for path, method in OUT_OF_NAMESPACE:
        resolve(path)  # raises Resolver404 if the route disappeared
        assert method in spec["paths"].get(path, {}), (
            f"{path}: documented endpoint missing operation {method!r} in openapi.yaml"
        )


def test_spec_version_matches_package(spec):
    # dev/release.sh bumps info.version in lockstep with pyproject.toml;
    # dev/check_release_versions.sh gates it at release time, this gates it in CI.
    assert spec["info"]["version"] == importlib.metadata.version("advisoryhub")
