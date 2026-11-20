#!/usr/bin/env python3
"""Guard the Dockerfile's base-image pins (run by prek and CI).

Two rules, both of which once failed silently:

1. **Every external base image sits on a literal ``FROM image:tag@sha256:…``
   line.** Dependabot's Dockerfile parser reads literal FROM lines only, so an
   image held in an ``ARG`` and used as ``FROM ${VAR}`` drops out of its
   updates without any error (that froze the DHI base from 2026-06 to 2026-11,
   until the Trivy gate failed on its unpatched Debian packages). Stages may
   still build ``FROM <earlier stage alias>``. The tag is required too: with a
   digest alone Dependabot has no version to bump.

2. **The Python patch in every ``dhi.io/python:<X.Y.Z>-…`` tag equals
   ``.python-version``** — dev = CI = prod. Dependabot bumps the image tag but
   never ``.python-version``, so its base-image PRs fail here until a human
   adds that bump (and, if needed, a newer uv in mise.toml that can download
   the new CPython) to the same PR.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<alias>\S+))?\s*$",
    re.IGNORECASE,
)
PINNED_RE = re.compile(r"^[^\s:@]+:\w[\w.-]{0,127}@sha256:[0-9a-f]{64}$")
DHI_PYTHON_RE = re.compile(r"^dhi\.io/python:(?P<version>\d+\.\d+\.\d+)-")


def _image_errors(image: str, where: str, aliases: set[str], python_version: str) -> list[str]:
    """Violations for the image of one FROM line (empty list = OK)."""
    if "$" in image:
        return [
            f"{where}: `FROM {image}` takes its image from a variable; Dependabot "
            "cannot see it. Pin the image on a literal `FROM image:tag@sha256:… AS "
            "<alias>` line and build `FROM <alias>` instead."
        ]
    if image.lower() in aliases:
        return []  # builds on an earlier stage; the pin lives on that stage's line
    if not PINNED_RE.match(image):
        return [
            f"{where}: `{image}` must be pinned as `image:tag@sha256:<digest>` "
            "(tag for Dependabot version bumps, digest for reproducibility)."
        ]
    dhi = DHI_PYTHON_RE.match(image)
    if dhi and dhi["version"] != python_version:
        return [
            f"{where}: DHI Python {dhi['version']} != .python-version "
            f"{python_version}. Bump both together (and mise.toml's uv if it "
            "cannot download that CPython yet)."
        ]
    return []


def check(dockerfile: str, python_version: str) -> list[str]:
    """Return one human-readable error per violation (empty list = OK)."""
    errors: list[str] = []
    aliases: set[str] = set()
    dhi_seen = False
    for lineno, line in enumerate(dockerfile.splitlines(), start=1):
        match = FROM_RE.match(line)
        if not match:
            continue
        image, alias = match["image"], match["alias"]
        errors += _image_errors(image, f"Dockerfile:{lineno}", aliases, python_version)
        if PINNED_RE.match(image) and DHI_PYTHON_RE.match(image):
            dhi_seen = True
        if alias:
            aliases.add(alias.lower())
    if not dhi_seen:
        errors.append(
            "Dockerfile: no pinned dhi.io/python base found; if the base image "
            "changed on purpose, update dev/check_dockerfile_bases.py with it."
        )
    return errors


def main() -> int:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    python_version = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
    errors = check(dockerfile, python_version)
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
