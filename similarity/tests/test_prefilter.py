from __future__ import annotations

import pytest

from advisories.models import Advisory, State
from similarity.prefilter import candidate_advisories

pytestmark = pytest.mark.django_db


@pytest.fixture
def project(make_project):
    return make_project("prefilter-proj")


@pytest.fixture
def other_project(make_project):
    return make_project("prefilter-other")


def test_same_project_only_and_excludes_self(project, other_project):
    target = Advisory.objects.create(
        project=project, summary="SQL injection in the login form handler"
    )
    sibling = Advisory.objects.create(
        project=project, summary="SQL injection in the login form validator"
    )
    foreign = Advisory.objects.create(
        project=other_project, summary="SQL injection in the login form handler"
    )
    result = candidate_advisories(target, target.to_payload(), limit=10)
    pks = {advisory.pk for advisory in result}
    assert sibling.pk in pks
    assert target.pk not in pks
    assert foreign.pk not in pks


def test_identifier_intersection_force_included(project):
    target = Advisory.objects.create(
        project=project,
        summary="Completely different wording about a parser bug",
        aliases=["CVE-2026-1234"],
    )
    by_alias = Advisory.objects.create(
        project=project, summary="Unrelated text entirely", aliases=["CVE-2026-1234"]
    )
    by_assigned = Advisory.objects.create(
        project=project, summary="Also nothing in common", assigned_cve_id="CVE-2026-1234"
    )
    unrelated = Advisory.objects.create(
        project=project, summary="Zzz qqq xxx", aliases=["CVE-2020-9999"]
    )
    result = candidate_advisories(target, target.to_payload(), limit=10)
    pks = {advisory.pk for advisory in result}
    assert by_alias.pk in pks
    assert by_assigned.pk in pks
    assert unrelated.pk not in pks


def test_affected_package_overlap_included(project):
    affected = [{"package": {"ecosystem": "Maven", "name": "org.example:widget"}}]
    target = Advisory.objects.create(
        project=project, summary="A flaw described one way", affected=affected
    )
    same_package = Advisory.objects.create(
        project=project,
        summary="Totally different prose with no overlap",
        affected=[{"package": {"ecosystem": "Maven", "name": "org.example:widget"}}],
    )
    other_package = Advisory.objects.create(
        project=project,
        summary="Qqq zzz vvv",
        affected=[{"package": {"ecosystem": "Maven", "name": "org.example:gadget"}}],
    )
    result = candidate_advisories(target, target.to_payload(), limit=10)
    pks = {advisory.pk for advisory in result}
    assert same_package.pk in pks
    assert other_package.pk not in pks


def test_trigram_ranks_most_similar_first_and_honors_limit(project):
    target = Advisory.objects.create(
        project=project, summary="Cross-site scripting in the markdown renderer"
    )
    near = Advisory.objects.create(
        project=project, summary="Cross-site scripting in the markdown renderer toolbar"
    )
    far = Advisory.objects.create(
        project=project, summary="Cross-site scripting somewhere in the renderer"
    )
    result = candidate_advisories(target, target.to_payload(), limit=10)
    assert result and result[0].pk == near.pk

    limited = candidate_advisories(target, target.to_payload(), limit=1)
    assert [advisory.pk for advisory in limited] == [near.pk]
    assert far.pk not in {advisory.pk for advisory in limited}


def test_all_lifecycle_states_in_pool(project):
    target = Advisory.objects.create(project=project, aliases=["CVE-2026-7777"])
    states = [State.TRIAGE, State.DRAFT, State.PUBLISHED, State.DISMISSED]
    expected = {
        Advisory.objects.create(project=project, state=state, aliases=["CVE-2026-7777"]).pk
        for state in states
    }
    result = candidate_advisories(target, target.to_payload(), limit=10)
    assert expected <= {advisory.pk for advisory in result}


def test_empty_content_and_no_identifiers_yields_nothing(project):
    target = Advisory.objects.create(project=project)
    Advisory.objects.create(project=project, summary="Something on file")
    assert candidate_advisories(target, target.to_payload(), limit=10) == []
