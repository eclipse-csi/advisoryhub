"""Self-test for ``dev/check_dockerfile_bases.py``.

The guard keeps every Dockerfile base image visible to Dependabot (literal,
digest-pinned FROM lines; no ``FROM ${ARG}``) and the DHI Python patch in
lockstep with ``.python-version``. ``test_live_tree_passes`` doubles as the
proof that the committed Dockerfile satisfies both rules.

No database needed — pure string checks.
"""

from __future__ import annotations

import importlib.util
import pathlib
import textwrap

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "check_dockerfile_bases", REPO_ROOT / "dev" / "check_dockerfile_bases.py"
)
guard = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guard)

DIGEST = "a" * 64
DEV = f"dhi.io/python:3.14.10-debian13-dev@sha256:{DIGEST}"
RUNTIME = f"dhi.io/python:3.14.10-debian13@sha256:{DIGEST}"


def _check(dockerfile: str, python_version: str = "3.14.10") -> list[str]:
    return guard.check(textwrap.dedent(dockerfile), python_version)


def test_literal_pins_and_stage_aliases_pass():
    assert (
        _check(
            f"""
            FROM {DEV} AS dhi-dev
            FROM {RUNTIME} AS dhi-runtime
            FROM dhi-dev AS build
            FROM build AS app
            from DHI-RUNTIME as production
            """
        )
        == []
    )


def test_arg_held_image_is_flagged():
    errors = _check(
        f"""
        ARG BASE={DEV}
        FROM {DEV} AS dhi-dev
        FROM ${{BASE}} AS build
        FROM $BASE AS other
        """
    )
    assert len(errors) == 2
    assert all("variable" in e for e in errors)
    assert errors[0].startswith("Dockerfile:4:")


def test_unpinned_or_digest_only_image_is_flagged():
    errors = _check(
        f"""
        FROM {DEV} AS dhi-dev
        FROM ghcr.io/astral-sh/uv:0.13.9 AS no-digest
        FROM ghcr.io/astral-sh/uv@sha256:{DIGEST} AS no-tag
        """
    )
    assert len(errors) == 2
    assert all("image:tag@sha256" in e for e in errors)


def test_python_version_mismatch_is_flagged():
    errors = _check(
        f"""
        FROM {DEV} AS dhi-dev
        FROM {RUNTIME} AS dhi-runtime
        """,
        python_version="3.14.9",
    )
    assert len(errors) == 2
    assert all("3.14.10 != .python-version 3.14.9" in e for e in errors)


def test_missing_dhi_base_is_flagged():
    errors = _check(f"FROM docker.io/library/python:3.14.10-slim@sha256:{DIGEST} AS base\n")
    assert len(errors) == 1
    assert "no pinned dhi.io/python base" in errors[0]


def test_live_tree_passes():
    assert guard.main() == 0
