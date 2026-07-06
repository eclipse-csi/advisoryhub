#!/usr/bin/env python3
"""Re-vendor upstream-verbatim assets to the version pinned in their .VERSION file.

This is the *materialize* half of the vendored-asset updater. Version *discovery*
is done by Renovate's customManagers (see .github/renovate.json), which bump the
version token in a .VERSION file via the ``# renovate:`` annotation above it. This
script then makes the committed bytes match that pinned version: it downloads the
file(s), recomputes SHA-256, re-applies the OSV ``ECL-`` prefix patch, and rewrites
the .VERSION. Renovate runs it as a postUpgradeTask; humans run it via
``mise run update-vendor`` (e.g. after editing a .VERSION by hand).

Idempotent: re-running when everything already matches the pinned versions makes
no changes (so a no-op run leaves the working tree clean).

Stdlib only (urllib + hashlib). Usage:
  python3 dev/update_vendored_assets.py [asset ...]
assets: htmx altcha inter neoteroi schemas   (default: all)

neoteroi-mkdocs.css is a standalone vendored CSS *release asset* (not a Python
dependency — it styles the OAD-rendered API docs page); like htmx/Inter it is
tracked by Renovate via the github-releases datasource.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "advisoryhub-vendor-updater"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # trusted upstreams
        if resp.status != 200:
            raise RuntimeError(f"GET {url} -> HTTP {resp.status}")
        return resp.read()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes) -> bool:
    """Write ``data`` to ``path``; return True if the bytes changed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == data:
        return False
    path.write_bytes(data)
    return True


def _read_version(version_file: Path, pattern: str) -> str:
    text = version_file.read_text()
    m = re.search(pattern, text, re.MULTILINE)
    if not m:
        raise SystemExit(f"could not parse version from {version_file} (pattern: {pattern!r})")
    return m.group(1)


def _apply_osv_patch(schema_bytes: bytes) -> bytes:
    """Add the Eclipse ``ECL-`` prefix to OSV's id-namespace allowlist
    (``$defs/prefix.pattern``). Idempotent and version-robust: inserts ``ECL|`` as
    the first alternative right after the anchored opening group ``^(`` — the one
    structural element stable across OSV releases (the prefix LIST and any ``x_``
    wrapper have changed between versions; alternation order is irrelevant)."""
    data = json.loads(schema_bytes)
    pattern = data["$defs"]["prefix"]["pattern"]
    if "ECL" not in pattern:
        data["$defs"]["prefix"]["pattern"] = pattern.replace("^(", "^(ECL|", 1)
    return (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode()


# --------------------------------------------------------------------------- #
# per-asset materializers — each returns the list of (path, changed) it touched
# --------------------------------------------------------------------------- #
def do_htmx() -> list[tuple[Path, bool]]:
    vfile = ROOT / "static/htmx.VERSION"
    v = _read_version(vfile, r"^htmx (\S+)")
    url = f"https://unpkg.com/htmx.org@{v}/dist/htmx.min.js"
    data = _get(url)
    changed = [(ROOT / "static/htmx.min.js", _write(ROOT / "static/htmx.min.js", data))]
    body = (
        f"# renovate: datasource=npm depName=htmx.org\n"
        f"htmx {v}\n"
        f"sha256:{_sha256(data)}\n"
        f"upstream: {url}\n\n"
        f"Vendored verbatim. Updated by `mise run update-vendor` (Renovate automates\n"
        f"discovery). Manual fallback:\n"
        f"  curl -sSf -L https://unpkg.com/htmx.org@<VER>/dist/htmx.min.js -o static/htmx.min.js\n"
        f"  shasum -a 256 static/htmx.min.js  # then update this file\n"
    )
    changed.append((vfile, _write(vfile, body.encode())))
    return changed


def do_inter() -> list[tuple[Path, bool]]:
    vfile = ROOT / "static/fonts/Inter.VERSION"
    v = _read_version(vfile, r"^Inter (\S+)")
    files = {
        "InterVariable.woff2": f"https://rsms.me/inter/font-files/InterVariable.woff2?v={v}",
        "InterVariable-Italic.woff2": (
            f"https://rsms.me/inter/font-files/InterVariable-Italic.woff2?v={v}"
        ),
    }
    changed: list[tuple[Path, bool]] = []
    hashes: dict[str, str] = {}
    for name, url in files.items():
        data = _get(url)
        hashes[name] = _sha256(data)
        dest = ROOT / "static/fonts" / name
        changed.append((dest, _write(dest, data)))
    body = (
        f"# renovate: datasource=github-tags depName=rsms/inter extractVersion=^v(?<version>.+)$\n"
        f"Inter {v} — variable font (weight axis 100-900), self-hosted.\n"
        f"License: SIL Open Font License 1.1 — https://github.com/rsms/inter/blob/master/LICENSE.txt\n\n"
        f"upstream: {files['InterVariable.woff2']}\n"
        f"upstream: {files['InterVariable-Italic.woff2']}\n\n"
        f"{hashes['InterVariable.woff2']}  InterVariable.woff2\n"
        f"{hashes['InterVariable-Italic.woff2']}  InterVariable-Italic.woff2\n\n"
        f"Updated by `mise run update-vendor` (Renovate automates discovery).\n"
    )
    changed.append((vfile, _write(vfile, body.encode())))
    return changed


def do_altcha() -> list[tuple[Path, bool]]:
    vfile = ROOT / "static/altcha/altcha.VERSION"
    v = _read_version(vfile, r"version (\d+\.\d+\.\d+)")
    base = f"https://cdn.jsdelivr.net/npm/altcha@{v}"
    files = {
        "altcha.external.min.js": f"{base}/dist/external/altcha.min.js",
        "altcha.css": f"{base}/dist/external/altcha.css",
        "sha.worker.js": f"{base}/dist/workers/sha.js",
    }
    changed: list[tuple[Path, bool]] = []
    hashes: dict[str, str] = {}
    for name, url in files.items():
        data = _get(url)
        hashes[name] = _sha256(data)
        dest = ROOT / "static/altcha" / name
        changed.append((dest, _write(dest, data)))
    body = (
        f"# renovate: datasource=npm depName=altcha\n"
        f'ALTCHA self-hosted widget — "external" (strict-CSP) build, version {v}.\n'
        f"License: MIT — https://github.com/altcha-org/altcha/blob/main/LICENSE\n\n"
        f"The external build ships no inline <style> and no bundled Web Workers, so it\n"
        f"loads under the app's strict CSP with NO directive changes (see static/altcha/\n"
        f"usage in templates/intake/report.html + static/advisoryhub-altcha.js). Only the\n"
        f"SHA family is vendored: altcha-lib-py emits SHA-256 challenges only.\n\n"
        f"upstream: {files['altcha.external.min.js']}\n"
        f"upstream: {files['altcha.css']}\n"
        f"upstream: {files['sha.worker.js']}\n\n"
        f"{hashes['altcha.external.min.js']}  altcha.external.min.js\n"
        f"{hashes['altcha.css']}  altcha.css\n"
        f"{hashes['sha.worker.js']}  sha.worker.js\n\n"
        f"Updated by `mise run update-vendor` (Renovate automates discovery). Keep the\n"
        f"widget version aligned with the altcha / django-altcha Python deps.\n"
    )
    changed.append((vfile, _write(vfile, body.encode())))
    return changed


def do_neoteroi() -> list[tuple[Path, bool]]:
    # Standalone vendored CSS release asset (not a Python dep) — tracked by
    # Renovate via github-releases, version read from its own .VERSION.
    vfile = ROOT / "docs/assets/css/neoteroi-mkdocs.VERSION"
    v = _read_version(vfile, r"^neoteroi-mkdocs v(\S+)")
    url = f"https://github.com/Neoteroi/mkdocs-plugins/releases/download/v{v}/css-v{v}.css"
    data = _get(url)
    dest = ROOT / "docs/assets/css/neoteroi-mkdocs.css"
    changed = [(dest, _write(dest, data))]
    body = (
        f"# renovate: datasource=github-tags depName=Neoteroi/mkdocs-plugins extractVersion=^v(?<version>.+)$\n"
        f"neoteroi-mkdocs v{v} (css release asset, styles the OAD-rendered API page)\n"
        f"sha256:{_sha256(data)}\n"
        f"upstream: {url}\n\n"
        f"Standalone vendored CSS (not a Python dependency). Updated by\n"
        f"`mise run update-vendor` (Renovate automates discovery). Manual fallback: curl the\n"
        f"release asset above and re-run shasum.\n"
    )
    changed.append((vfile, _write(vfile, body.encode())))
    return changed


def do_schemas() -> list[tuple[Path, bool]]:
    vfile = ROOT / "publication/schemas/SCHEMAS.VERSION"
    text = vfile.read_text()
    osv_tag = _read_version(vfile, r"^osv-schema v(\S+)")
    cve_tag = _read_version(vfile, r"^cve-schema v(\S+)")
    sdir = ROOT / "publication/schemas"

    osv_url = f"https://raw.githubusercontent.com/ossf/osv-schema/v{osv_tag}/validation/schema.json"
    cve_base = f"https://raw.githubusercontent.com/CVEProject/cve-schema/v{cve_tag}/schema"
    sources: list[tuple[str, str, bool]] = [
        ("osv.upstream.json", osv_url, True),
        ("cve.upstream.json", f"{cve_base}/CVE_Record_Format.json", False),
        ("cvss/cvss-v2.0.json", f"{cve_base}/imports/cvss/cvss-v2.0.json", False),
        ("cvss/cvss-v3.0.json", f"{cve_base}/imports/cvss/cvss-v3.0.json", False),
        ("cvss/cvss-v3.1.json", f"{cve_base}/imports/cvss/cvss-v3.1.json", False),
        ("cvss/cvss-v4.0.json", f"{cve_base}/imports/cvss/cvss-v4.0.json", False),
    ]
    changed: list[tuple[Path, bool]] = []
    hashes: dict[str, str] = {}
    for relpath, url, is_osv in sources:
        data = _get(url)
        if is_osv:
            data = _apply_osv_patch(data)
        hashes[relpath] = _sha256(data)
        dest = sdir / relpath
        changed.append((dest, _write(dest, data)))
    # CSAF is a fixed OASIS document (version 2.0) — re-fetch verbatim, no tag.
    csaf = _get("https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json")
    hashes["csaf.upstream.json"] = _sha256(csaf)
    changed.append((sdir / "csaf.upstream.json", _write(sdir / "csaf.upstream.json", csaf)))

    # Rewrite SCHEMAS.VERSION: keep the pinned-tag header lines (with their
    # ``# renovate:`` annotations) verbatim, regenerate the hash block.
    header = text.split("\n\n# sha256", 1)[0]  # everything up to the hash block marker
    hash_block = "\n".join(
        f"{hashes[name]}  {name}"
        for name in (
            "osv.upstream.json",
            "csaf.upstream.json",
            "cve.upstream.json",
            "cvss/cvss-v2.0.json",
            "cvss/cvss-v3.0.json",
            "cvss/cvss-v3.1.json",
            "cvss/cvss-v4.0.json",
        )
    )
    body = (
        f"{header}\n\n# sha256 <relpath> (verified by dev/check_vendored_assets.sh)\n{hash_block}\n"
    )
    changed.append((vfile, _write(vfile, body.encode())))
    return changed


ASSETS = {
    "htmx": do_htmx,
    "inter": do_inter,
    "altcha": do_altcha,
    "neoteroi": do_neoteroi,
    "schemas": do_schemas,
}


def main(argv: list[str]) -> int:
    selected = argv or list(ASSETS)
    unknown = [a for a in selected if a not in ASSETS]
    if unknown:
        raise SystemExit(f"unknown asset(s): {', '.join(unknown)}; known: {', '.join(ASSETS)}")
    any_changed = False
    for name in selected:
        touched = ASSETS[name]()
        changes = [p for p, c in touched if c]
        if changes:
            any_changed = True
            for p in changes:
                print(f"updated {p.relative_to(ROOT)}")
        else:
            print(f"{name}: up to date")
    print("changes written" if any_changed else "all assets already current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
