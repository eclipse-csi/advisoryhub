"""Query-count budget guards for the hottest advisory pages.

Why these tests exist
---------------------
PERF-1 (fixed 2026-07-01, commit 0fd71cb) was a ~100-query N+1 on the
advisory detail page: every permission predicate re-read the viewer's group
memberships. The memoization tests in ``test_permissions.py`` pin that
specific fix at the permission layer; these budgets guard the *pages* so the
next O(N) blowup — wherever it lands — fails CI deterministically.

The detail page lazy-loads its heavy panels over HTMX (``hx-trigger="load"``
in ``templates/advisories/detail.html``), so the shell, the timeline
fragment, and the access panel are budgeted as separate GETs: a budget on
the shell alone would never see a timeline or grants-panel N+1.

Every per-row collection is seeded well above ``HEADROOM`` (comments 15,
timeline events ~20, versions 12, grants+invitations 9, list rows 30), so a
regression issuing even one query per row overshoots its budget several
times over and cannot hide inside the headroom.

How to update a budget (and how not to)
---------------------------------------
On failure pytest-django prints every captured query:

- Repeated SQL shapes differing only in parameters = an N+1. Fix the code;
  do NOT bump the budget.
- A deliberate new constant cost (a new context processor, a new sidebar
  ``.exists()``, a Django upgrade shifting session/savepoint behaviour):
  re-measure and set the constant to measured + HEADROOM, with a dated
  comment naming the cause.
- ``HEADROOM`` must stay well below every seeded row count above.

Known, deliberately-pinned per-row costs (bounded by participant count, not
timeline length): the access panel resolves ``grant.principal()`` per grant
row, ``mention_candidates`` re-checks ``can_view`` per candidate user, and a
non-team viewer's permission predicates each re-read the explicit grants
(``_explicit_grant_rank`` is intentionally not memoized — see
``test_permissions.py``). The budgets hold those constant at this fixture's
fixed seeding so they cannot silently grow.
"""

from __future__ import annotations

import pytest
from django.contrib.auth.models import Group
from django.urls import reverse

from access import services as access_services
from access.models import Permission
from advisories.models import Advisory
from advisories.services import record_advisory_version
from audit.models import Action
from audit.services import record
from comments.services import add_comment

HEADROOM = 3

# Budgets measured 2026-07-06 (see module docstring for the update policy).
DETAIL_OWNER_BUDGET = 50 + HEADROOM
DETAIL_COLLABORATOR_BUDGET = 63 + HEADROOM
TIMELINE_OWNER_BUDGET = 25 + HEADROOM
TIMELINE_COLLABORATOR_BUDGET = 29 + HEADROOM
ACCESS_PANEL_BUDGET = 28 + HEADROOM
LIST_BUDGET = 17 + HEADROOM


@pytest.fixture
def rich_world(make_user, make_project, settings):
    """One advisory with every per-row dimension seeded far above HEADROOM."""
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    owner = make_user(email="owner@example.org")
    project = make_project("hot-project", team_members=[owner])
    advisory = Advisory.objects.create(
        project=project, summary="Heap overflow in widget parser", details="rev 0"
    )

    # Collaborator via a *group* grant: the highest permission-query role on
    # the detail page (per-predicate explicit-grant reads, tier-B timeline).
    collaborator = make_user(email="collab@example.org")
    collab_group = Group.objects.create(name="hot-collaborators")
    collaborator.groups.add(collab_group)
    access_services.grant_to_group(advisory, collab_group, Permission.COLLABORATOR, by=owner)

    # 6 grants total (4 user + 2 group) + 3 pending invitations; each grant
    # and invitation also emits its ACCESS_GRANTED / INVITATION_CREATED
    # timeline event.
    viewer = make_user(email="viewer@example.org")
    access_services.grant_to_user(advisory, viewer, Permission.VIEWER, by=owner)
    for i in range(3):
        extra = make_user(email=f"granted{i}@example.org")
        access_services.grant_to_user(advisory, extra, Permission.VIEWER, by=owner)
    observers = Group.objects.create(name="hot-observers")
    access_services.grant_to_group(advisory, observers, Permission.VIEWER, by=owner)
    for i in range(3):
        access_services.invite_email(
            advisory, f"pending{i}@example.org", Permission.VIEWER, by=owner
        )
    # Revocation events exercise both principal-label kinds in the timeline.
    record(
        action=Action.ACCESS_REVOKED,
        actor=owner,
        advisory=advisory,
        previous_value={
            "principal_type": "user",
            "principal_id": viewer.pk,
            "permission": "viewer",
        },
    )
    record(
        action=Action.ACCESS_REVOKED,
        actor=owner,
        advisory=advisory,
        previous_value={
            "principal_type": "group",
            "principal_id": observers.pk,
            "permission": "viewer",
        },
    )

    # 12 appended versions, each with its ADVISORY_EDITED event (varying
    # details keeps every version in details_history; the version-run
    # payloads exercise the timeline coalescer).
    for i in range(1, 13):
        advisory.details = f"rev {i}"
        advisory.save(update_fields=["details"])
        version = record_advisory_version(advisory, editor=owner)
        record(
            action=Action.ADVISORY_EDITED,
            actor=owner,
            advisory=advisory,
            new_value={"version": version.version},
            metadata={"changed_fields": ["details"]},
        )

    # 15 comments from 3 distinct authors; internal ones from the owner only
    # (posting internal requires collaborator+, and mixing tiers exercises
    # the viewer-side exclusion in the collaborator/owner timeline tests).
    for i in range(3):
        add_comment(advisory, author=owner, body=f"internal note {i}", internal=True)
    authors = [owner, collaborator, viewer]
    for i in range(12):
        add_comment(advisory, author=authors[i % 3], body=f"comment {i}")

    return {
        "advisory": advisory,
        "owner": owner,
        "collaborator": collaborator,
        "project": project,
    }


@pytest.fixture
def list_world(make_user, make_project, settings):
    """A member of one project with 30 visible advisories (single list page)."""
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    member = make_user(email="lister@example.org")
    project = make_project("list-project", team_members=[member])
    for i in range(30):
        Advisory.objects.create(project=project, summary=f"finding {i}")
    return {"member": member}


def _assert_budget(client, user, url, budget, django_assert_max_num_queries):
    """Warm up once, then budget the steady-state GET.

    The warm-up request absorbs the deliberate first-request-only work: the
    detail view's first-seen branch (AdvisoryVisit INSERT + audit row) and
    the maintenance-mode cache fill (the autouse ``_clear_cache`` fixture
    empties the cache before every test).
    """
    client.force_login(user)
    warm = client.get(url)
    assert warm.status_code == 200
    with django_assert_max_num_queries(budget):
        response = client.get(url)
    assert response.status_code == 200
    return response


@pytest.mark.django_db
def test_advisory_detail_query_budget_owner(client, rich_world, django_assert_max_num_queries):
    """The detail shell stays flat as a project security-team member.

    Comments/timeline/grants are lazy HTMX panels — they must not be able to
    push shell queries up with their row counts.
    """
    url = reverse("advisories:detail", args=[rich_world["advisory"].advisory_id])
    _assert_budget(
        client, rich_world["owner"], url, DETAIL_OWNER_BUDGET, django_assert_max_num_queries
    )


@pytest.mark.django_db
def test_advisory_detail_query_budget_collaborator(
    client, rich_world, django_assert_max_num_queries
):
    """Same shell as a group-granted collaborator.

    Pins the per-predicate explicit-grant reads (deliberately unmemoized) so
    their constant cannot grow with future predicates or per-row leaks.
    """
    url = reverse("advisories:detail", args=[rich_world["advisory"].advisory_id])
    _assert_budget(
        client,
        rich_world["collaborator"],
        url,
        DETAIL_COLLABORATOR_BUDGET,
        django_assert_max_num_queries,
    )


@pytest.mark.django_db
def test_timeline_fragment_query_budget_owner(client, rich_world, django_assert_max_num_queries):
    """The merged comments+audit timeline (PERF-1's landing zone) stays flat
    regardless of comment/event count — its select_related/prefetch_related
    are load-bearing."""
    url = reverse("comments:timeline", args=[rich_world["advisory"].advisory_id])
    _assert_budget(
        client, rich_world["owner"], url, TIMELINE_OWNER_BUDGET, django_assert_max_num_queries
    )


@pytest.mark.django_db
def test_timeline_fragment_query_budget_collaborator(
    client, rich_world, django_assert_max_num_queries
):
    """Tier-B event filtering and internal-comment handling stay flat too."""
    url = reverse("comments:timeline", args=[rich_world["advisory"].advisory_id])
    _assert_budget(
        client,
        rich_world["collaborator"],
        url,
        TIMELINE_COLLABORATOR_BUDGET,
        django_assert_max_num_queries,
    )


@pytest.mark.django_db
def test_access_panel_query_budget(client, rich_world, django_assert_max_num_queries):
    """The grants panel (owner-only) with 6 grants + 3 invitations.

    Pins the known per-grant ``principal()`` lookup at this seeding so it
    cannot silently get worse.
    """
    url = reverse("access:panel", args=[rich_world["advisory"].advisory_id])
    _assert_budget(
        client, rich_world["owner"], url, ACCESS_PANEL_BUDGET, django_assert_max_num_queries
    )


@pytest.mark.django_db
def test_advisory_list_query_budget(client, list_world, django_assert_max_num_queries):
    """One page of 30 advisories renders in a flat number of queries (the
    visit markers ride inside the page query; project comes select_related)."""
    _assert_budget(
        client,
        list_world["member"],
        reverse("advisories:list"),
        LIST_BUDGET,
        django_assert_max_num_queries,
    )
