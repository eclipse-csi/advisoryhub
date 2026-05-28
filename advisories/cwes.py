"""Vendored CWE catalog (id + name + abstraction).

The JSON file under ``advisories/data/cwes.json`` is a slim projection of
MITRE's official ``cwec_latest.xml`` (Weakness entries only, no Categories
or Views, ``Deprecated`` rows dropped). To refresh, download
https://cwe.mitre.org/data/xml/cwec_latest.xml.zip and rewrite the JSON
by iterating the ``<Weakness>`` elements and keeping only
``{id, name, abstraction}``.

Authors pick CWE ids from this list in the advisory form. Anything not in
the catalog is rejected server-side, so the UI cannot be bypassed by a
hand-crafted POST.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA_PATH = Path(__file__).resolve().parent / "data" / "cwes.json"


@lru_cache(maxsize=1)
def _catalog() -> dict:
    with _DATA_PATH.open("rb") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def cwe_by_id() -> dict[str, dict]:
    """Return ``{CWE-id: {id, name, abstraction}}`` for every weakness."""
    return {w["id"]: w for w in _catalog()["weaknesses"]}


def is_known(cwe_id: str) -> bool:
    return cwe_id.upper() in cwe_by_id()


def name_for(cwe_id: str) -> str | None:
    entry = cwe_by_id().get(cwe_id.upper())
    return entry["name"] if entry else None


def catalog_version() -> str:
    return _catalog().get("version", "")


def all_entries() -> list[dict]:
    """Stable, id-sorted list of ``{id, name, abstraction}`` entries."""
    return list(_catalog()["weaknesses"])
