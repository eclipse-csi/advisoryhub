from __future__ import annotations

import re

import pytest
from django.urls import reverse

from advisories.models import Advisory, ReviewStatus, State


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    project_a = make_project("project-a")
    project_b = make_project("project-b")
    a = Advisory.objects.create(project=project_a, summary="HTTP/2 header smuggling")
    b = Advisory.objects.create(
        project=project_b,
        summary="Path traversal",
        state=State.PUBLISHED,
        published_at=__import__("django").utils.timezone.now(),
    )
    c = Advisory.objects.create(
        project=project_a,
        summary="Reflected XSS",
        review_status=ReviewStatus.SUBMITTED,
    )
    d = Advisory.objects.create(
        project=project_a,
        summary="Memory disclosure",
        state=State.PUBLISHED,
        republish_required=True,
        aliases=["CVE-2026-9999"],
    )
    return {
        "admin": admin,
        "project_a": project_a,
        "project_b": project_b,
        "a": a,
        "b": b,
        "c": c,
        "d": d,
    }


def _ids_in_response(response) -> set[str]:
    body = response.content.decode()
    return {a.advisory_id for a in (Advisory.objects.all()) if a.advisory_id in body}


@pytest.mark.django_db
def test_no_filters_lists_all_visible(client, setup):
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"))
    ids = _ids_in_response(r)
    assert {
        setup["a"].advisory_id,
        setup["b"].advisory_id,
        setup["c"].advisory_id,
        setup["d"].advisory_id,
    }.issubset(ids)


@pytest.mark.django_db
def test_filter_by_project_slug(client, setup):
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), {"project": str(setup["project_b"].id)})
    ids = _ids_in_response(r)
    assert setup["b"].advisory_id in ids
    assert setup["a"].advisory_id not in ids


@pytest.mark.django_db
def test_project_filter_options_show_slug_as_detail(client, setup):
    """The project filter is a smart combobox: the slug rides on
    data-combobox-detail (shown as a second line + matched), not inline in the
    option label."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list")).content.decode()
    p = setup["project_b"]
    assert f'data-combobox-detail="{p.slug}"' in body
    assert f"{p.name} ({p.slug})" not in body


@pytest.mark.django_db
def test_filter_by_state(client, setup):
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), {"state": "published"})
    ids = _ids_in_response(r)
    assert setup["b"].advisory_id in ids
    assert setup["d"].advisory_id in ids
    assert setup["a"].advisory_id not in ids


@pytest.mark.django_db
def test_state_tabs_render_with_counts(client, setup):
    """The state tab strip renders All + the four states, each with the count of
    matching advisories. Fixture: 2 draft (a, c), 2 published (b, d)."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list")).content.decode()
    # Label immediately precedes its count span (see list.html).
    assert 'All<span class="state-tabs__count">4</span>' in body
    assert 'Triage<span class="state-tabs__count">0</span>' in body
    assert 'Draft<span class="state-tabs__count">2</span>' in body
    assert 'Published<span class="state-tabs__count">2</span>' in body
    assert 'Dismissed<span class="state-tabs__count">0</span>' in body


@pytest.mark.django_db
def test_active_state_tab_marked(client, setup):
    """Exactly one tab is active; ?state=draft marks the Draft tab, default marks All."""
    client.force_login(setup["admin"])

    body = client.get(reverse("advisories:list"), {"state": "draft"}).content.decode()
    assert body.count('aria-current="page"') == 1
    active = re.search(r"<a[^>]*is-active[^>]*>(.*?)</a>", body, re.S)
    assert active and "Draft" in active.group(1)

    body = client.get(reverse("advisories:list")).content.decode()
    assert body.count('aria-current="page"') == 1
    active = re.search(r"<a[^>]*is-active[^>]*>(.*?)</a>", body, re.S)
    assert active and "All" in active.group(1)


@pytest.mark.django_db
def test_tab_href_preserves_other_filters(client, setup):
    """A tab link carries the current search/project filters and resets paging."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list"), {"q": "smuggling"}).content.decode()
    m = re.search(r'href="([^"]*state=draft[^"]*)"', body)
    assert m, "no Draft tab href found"
    href = m.group(1)
    assert "q=smuggling" in href
    assert "page=" not in href


@pytest.mark.django_db
def test_search_form_preserves_active_state(client, setup):
    """The active tab survives a search submit (hidden state input in the form);
    on the All tab there is no such hidden input."""
    client.force_login(setup["admin"])

    body = client.get(reverse("advisories:list"), {"state": "draft"}).content.decode()
    assert '<input type="hidden" name="state" value="draft">' in body

    body = client.get(reverse("advisories:list")).content.decode()
    assert 'type="hidden" name="state"' not in body


@pytest.mark.django_db
def test_state_tab_does_not_show_clear_link(client, setup):
    """Selecting a state tab must not surface the form's Clear link — the All tab
    is the clear-state affordance. Clear belongs to the search/project filters
    only."""
    client.force_login(setup["admin"])

    body = client.get(reverse("advisories:list"), {"state": "draft"}).content.decode()
    assert ">Clear<" not in body

    body = client.get(reverse("advisories:list"), {"q": "smuggling"}).content.decode()
    assert ">Clear<" in body


@pytest.mark.django_db
def test_review_status_param_ignored(client, setup):
    """The review-status filter was removed; the param no longer narrows."""
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), {"review_status": "submitted"})
    ids = _ids_in_response(r)
    assert {
        setup["a"].advisory_id,
        setup["b"].advisory_id,
        setup["c"].advisory_id,
        setup["d"].advisory_id,
    }.issubset(ids)


@pytest.mark.django_db
def test_search_q_summary(client, setup):
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), {"q": "smuggling"})
    ids = _ids_in_response(r)
    assert ids == {setup["a"].advisory_id}


@pytest.mark.django_db
def test_search_q_alias(client, setup):
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), {"q": "CVE-2026-9999"})
    ids = _ids_in_response(r)
    assert setup["d"].advisory_id in ids


@pytest.mark.django_db
def test_invalid_state_silently_ignored(client, setup):
    """An unknown state name doesn't blow up — it just isn't applied."""
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), {"state": "abandoned"})
    assert r.status_code == 200


@pytest.mark.django_db
def test_pagination(client, setup, make_project):
    """A high page_size shouldn't blow up; a low one paginates."""
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), {"page_size": "2"})
    assert r.status_code == 200
    # 4 advisories ÷ 2 page-size → has_next on page 1
    body = r.content.decode()
    assert "Next" in body
