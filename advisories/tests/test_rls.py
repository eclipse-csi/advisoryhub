"""Row-level-security backstop tests (INV-CONF-2).

These prove the DB policy enforces advisory visibility *independently of the
ORM filter* — a query that "forgets" ``visible_to`` still returns only the rows
the principal may see. The dev/CI Postgres role is a superuser (RLS-exempt), so
each test creates a throwaway ``NOSUPERUSER`` role, ``SET ROLE``s to it, sets the
principal GUC, and runs a bare query — the only way to exercise the policy
locally. Production runs under such a non-superuser role permanently
(running-in-production §7).
"""

from __future__ import annotations

import pytest
from django.db import connection

from advisories.models import Advisory
from common import rls

pytestmark = pytest.mark.django_db

_PROBE_ROLE = "advisoryhub_rls_probe"


def _make_probe_role() -> None:
    # Idempotent: callable more than once per test. A DROP+CREATE would fail the
    # second time ("role cannot be dropped because some objects depend on it:
    # privileges …") once the role holds grants. Created inside the test
    # transaction, so it rolls back with everything else.
    with connection.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [_PROBE_ROLE])
        if cur.fetchone() is None:
            cur.execute(f'CREATE ROLE "{_PROBE_ROLE}" NOSUPERUSER')
        cur.execute(f'GRANT USAGE ON SCHEMA public TO "{_PROBE_ROLE}"')
        cur.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{_PROBE_ROLE}"')


def _visible_advisory_ids_under_rls(user) -> set[str]:
    """Advisory ids a bare ``.all()`` returns while connected as a non-superuser
    role with the RLS principal GUC set to ``user`` (admins/system bypass)."""
    _make_probe_role()
    rls.set_principal_for_user(user)
    try:
        with connection.cursor() as cur:
            cur.execute(f'SET ROLE "{_PROBE_ROLE}"')
            try:
                # Deliberately UNFILTERED — RLS is the only thing scoping this.
                return set(Advisory.objects.values_list("advisory_id", flat=True))
            finally:
                cur.execute("RESET ROLE")
    finally:
        rls.clear_principal()


@pytest.fixture
def rls_world(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="member@example.org")
    outsider = make_user(email="outsider@example.org")
    proj = make_project("proj-a", team_members=[member])
    other = make_project("proj-b")
    a_member = Advisory.objects.create(project=proj, summary="member's advisory")
    a_other = Advisory.objects.create(project=other, summary="other project's advisory")
    return {
        "admin": admin,
        "member": member,
        "outsider": outsider,
        "a_member": a_member,
        "a_other": a_other,
    }


def test_backstop_outsider_sees_no_rows(rls_world):
    # The app "forgot" to filter (bare .all()); RLS still returns nothing.
    assert _visible_advisory_ids_under_rls(rls_world["outsider"]) == set()


def test_backstop_unset_principal_is_fail_closed(rls_world):
    # No principal at all (e.g. an unauthenticated path) → no rows.
    _make_probe_role()
    rls.clear_principal()
    with connection.cursor() as cur:
        cur.execute(f'SET ROLE "{_PROBE_ROLE}"')
        try:
            assert set(Advisory.objects.values_list("advisory_id", flat=True)) == set()
        finally:
            cur.execute("RESET ROLE")


def test_member_sees_only_their_project(rls_world):
    assert _visible_advisory_ids_under_rls(rls_world["member"]) == {
        rls_world["a_member"].advisory_id
    }


def test_admin_principal_bypasses(rls_world):
    assert _visible_advisory_ids_under_rls(rls_world["admin"]) == {
        rls_world["a_member"].advisory_id,
        rls_world["a_other"].advisory_id,
    }


def test_explicit_grant_is_honored(rls_world, make_user):
    from access.models import Permission as AccessPermission
    from access.services import grant_to_user

    grantee = make_user(email="grantee@example.org")
    grant_to_user(rls_world["a_other"], grantee, AccessPermission.VIEWER, by=rls_world["admin"])
    assert _visible_advisory_ids_under_rls(grantee) == {rls_world["a_other"].advisory_id}


@pytest.mark.parametrize("principal", ["outsider", "member", "admin"])
def test_rls_matches_visible_to(rls_world, principal):
    """Drift guard: the SQL policy and AdvisoryQuerySet.visible_to agree."""
    user = rls_world[principal]
    app_ids = set(Advisory.objects.visible_to(user).values_list("advisory_id", flat=True))
    assert app_ids == _visible_advisory_ids_under_rls(user)


def test_child_table_inherits_visibility(rls_world, make_user):
    """A comment is visible iff its advisory is (deferring child policy)."""
    from comments.models import AdvisoryComment

    AdvisoryComment.objects.create(
        advisory=rls_world["a_member"], author=rls_world["member"], body="mine"
    )
    AdvisoryComment.objects.create(
        advisory=rls_world["a_other"], author=rls_world["admin"], body="other"
    )

    def comment_bodies_under_rls(user) -> set[str]:
        _make_probe_role()
        rls.set_principal_for_user(user)
        try:
            with connection.cursor() as cur:
                cur.execute(f'SET ROLE "{_PROBE_ROLE}"')
                try:
                    return set(AdvisoryComment.objects.values_list("body", flat=True))
                finally:
                    cur.execute("RESET ROLE")
        finally:
            rls.clear_principal()

    assert comment_bodies_under_rls(rls_world["member"]) == {"mine"}
    assert comment_bodies_under_rls(rls_world["outsider"]) == set()
