from __future__ import annotations

import json

from django.urls import reverse


def test_projects_json_returns_slug_and_name_only(db, client, make_project):
    p = make_project("alpha")
    make_project("beta")
    resp = client.get(reverse("intake:projects_json"))
    assert resp.status_code == 200
    payload = json.loads(resp.content)
    assert isinstance(payload, list)
    assert len(payload) == 2
    for entry in payload:
        # Hard guard: any new key indicates an accidental leak — fail loudly.
        assert set(entry.keys()) == {"slug", "name"}, entry
    slugs = {e["slug"] for e in payload}
    assert p.slug in slugs


def test_projects_json_search_filter(db, client, make_project):
    make_project("alpha-core")
    make_project("beta")
    resp = client.get(reverse("intake:projects_json") + "?q=alpha")
    assert resp.status_code == 200
    payload = json.loads(resp.content)
    assert len(payload) == 1
    assert payload[0]["slug"] == "alpha-core"


def test_projects_json_anonymous_access(db, client, make_project):
    make_project("alpha")
    resp = client.get(reverse("intake:projects_json"))
    assert resp.status_code == 200


def test_projects_json_cache_control(db, client, make_project):
    make_project("alpha")
    resp = client.get(reverse("intake:projects_json"))
    assert "max-age=300" in resp["Cache-Control"]
