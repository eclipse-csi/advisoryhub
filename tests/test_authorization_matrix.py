"""Authorization matrix — every advisory-scoped endpoint denies non-members.

Two guards behind INV-CONF-2 / INV-AUTH-1:

1. ``test_advisory_get_routes_deny_outsider_and_anonymous`` — a generic sweep
   that discovers every URL whose only required argument is ``advisory_id`` and
   asserts an outsider and an anonymous user never get a ``200`` (a content
   leak). A new advisory-scoped GET endpoint that forgets its permission check
   fails this by construction.
2. capability cases on the list / detail views — viewer / collaborator / owner /
   admin see what they should, and a published advisory stays invisible without
   an explicit grant (INV-AUTH-7).

Scope of the generic sweep: **GET** on single-``advisory_id`` routes — the
read-leak surface. Write authorization and child-id routes (comment-id, task-id)
are covered by the capability cases below and the RLS backstop tests
(``advisories/tests/test_rls.py``), not re-enumerated here. Tests run as the
superuser DB role, so this exercises the *application-layer* chokepoint; the
DB-level RLS backstop is proven separately in ``test_rls.py``.
"""

from __future__ import annotations

import pytest
from django.urls import URLPattern, URLResolver, get_resolver, reverse

from advisories.models import Advisory, State

pytestmark = pytest.mark.django_db


def _advisory_id_only_routes() -> list[str]:
    """Namespaced names of routes whose required kwargs are exactly {advisory_id}."""
    names: list[str] = []

    def walk(resolver: URLResolver, prefix: str) -> None:
        for pattern in resolver.url_patterns:
            if isinstance(pattern, URLResolver):
                ns = f"{prefix}{pattern.namespace}:" if pattern.namespace else prefix
                walk(pattern, ns)
            elif isinstance(pattern, URLPattern) and pattern.name:
                if set(pattern.pattern.regex.groupindex) == {"advisory_id"}:
                    names.append(prefix + pattern.name)

    walk(get_resolver(), "")
    return sorted(set(names))


@pytest.fixture
def matrix_world(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="member@example.org")
    outsider = make_user(email="outsider@example.org")
    project = make_project("proj-a", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="secret summary")
    return {
        "admin": admin,
        "member": member,
        "outsider": outsider,
        "project": project,
        "advisory": advisory,
    }


def test_generic_sweep_finds_routes():
    # Guard against the sweep silently testing nothing (e.g. a converter rename):
    # there are dozens of advisory_id-only routes across the apps.
    assert len(_advisory_id_only_routes()) >= 15


def test_advisory_get_routes_deny_outsider_and_anonymous(client, matrix_world):
    advisory = matrix_world["advisory"]
    outsider = matrix_world["outsider"]
    leaks: list[str] = []
    unreversible: list[str] = []
    for name in _advisory_id_only_routes():
        try:
            url = reverse(name, kwargs={"advisory_id": advisory.advisory_id})
        except Exception:  # noqa: BLE001 — surfaced via the assertion below
            unreversible.append(name)
            continue
        client.logout()
        if client.get(url).status_code == 200:
            leaks.append(f"anonymous→200 {name}")
        client.force_login(outsider)
        if client.get(url).status_code == 200:
            leaks.append(f"outsider→200 {name}")
    assert not unreversible, f"could not reverse advisory_id routes: {unreversible}"
    assert not leaks, "advisory-scoped GET leaked to a non-member: " + ", ".join(leaks)


def test_detail_visibility_matrix(client, matrix_world, make_user):
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    advisory = matrix_world["advisory"]
    url = reverse("advisories:detail", kwargs={"advisory_id": advisory.advisory_id})

    viewer = make_user(email="viewer@example.org")
    collaborator = make_user(email="collab@example.org")
    grant_to_user(advisory, viewer, AccessPermission.VIEWER, by=matrix_world["member"])
    grant_to_user(advisory, collaborator, AccessPermission.COLLABORATOR, by=matrix_world["member"])

    for user in (matrix_world["admin"], matrix_world["member"], viewer, collaborator):
        client.force_login(user)
        assert client.get(url).status_code == 200, user.email

    client.force_login(matrix_world["outsider"])
    assert client.get(url).status_code in (403, 404)

    client.logout()
    assert client.get(url).status_code in (302, 403, 404)


def test_published_detail_denied_without_grant(client, matrix_world):
    """INV-AUTH-7: publication grants no implicit read access inside AdvisoryHub."""
    advisory = matrix_world["advisory"]
    advisory.state = State.PUBLISHED
    advisory.save()
    url = reverse("advisories:detail", kwargs={"advisory_id": advisory.advisory_id})
    client.force_login(matrix_world["outsider"])
    assert client.get(url).status_code in (403, 404)


def test_list_shows_only_visible(client, matrix_world, make_project):
    """advisory_list filters through visible_to: each principal sees only theirs."""
    mine = matrix_world["advisory"]
    other = Advisory.objects.create(project=make_project("proj-b"), summary="other project secret")
    list_url = reverse("advisories:list")
    mine_link = reverse("advisories:detail", kwargs={"advisory_id": mine.advisory_id})
    other_link = reverse("advisories:detail", kwargs={"advisory_id": other.advisory_id})

    client.force_login(matrix_world["member"])
    body = client.get(list_url).content.decode()
    assert mine_link in body
    assert other_link not in body

    client.force_login(matrix_world["outsider"])
    body = client.get(list_url).content.decode()
    assert mine_link not in body
    assert other_link not in body

    client.force_login(matrix_world["admin"])
    body = client.get(list_url).content.decode()
    assert mine_link in body
    assert other_link in body
