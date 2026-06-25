from __future__ import annotations

import re
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

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


def _ids_in_order(response) -> list[str]:
    """Advisory ids in the order their rows appear in the table body.

    Each row renders a `/advisories/<id>/` link (in the row's data-href and its
    first-cell anchor), so capturing those in document order — deduped, and
    restricted to known ids so `/advisories/new/` etc. are ignored — yields the
    rendered sort order. (`_ids_in_response` returns a set and is order-blind.)
    """
    body = response.content.decode()
    known = {a.advisory_id for a in Advisory.objects.all()}
    seen: list[str] = []
    for m in re.finditer(r"/advisories/([A-Za-z0-9-]+)/", body):
        aid = m.group(1)
        if aid in known and aid not in seen:
            seen.append(aid)
    return seen


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
def test_state_tab_counts_nonadmin_multiple_per_state(client, make_user, make_project):
    """Regression: tab counts for a non-admin (security-team) viewer must reflect
    the true per-state totals even with more than one advisory in a state.

    Advisory's default ``-created_at`` ordering was being folded into the per-tab
    GROUP BY (Django appends ordering columns to the grouping), splitting each
    state into one row per distinct ``created_at``; the view's dict comprehension
    then kept only the last row per state and undercounted. The admin list path
    (``Advisory.objects.all()``, no ``.distinct()``) doesn't trip the fold, so this
    regression only bites the team/grant path — hence a non-admin viewer here.
    """
    viewer = make_user(email="viewer@example.org")
    project = make_project("teamed", team_members=[viewer])
    for i in range(3):
        Advisory.objects.create(project=project, summary=f"draft-{i}", state=State.DRAFT)
    for i in range(2):
        Advisory.objects.create(
            project=project,
            summary=f"pub-{i}",
            state=State.PUBLISHED,
            published_at=timezone.now(),
        )
    client.force_login(viewer)
    body = client.get(reverse("advisories:list")).content.decode()
    assert 'All<span class="state-tabs__count">5</span>' in body
    assert 'Triage<span class="state-tabs__count">0</span>' in body
    assert 'Draft<span class="state-tabs__count">3</span>' in body
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


# --------------------------------------------------------------------------- #
# Active search (HTMX fragment)
# --------------------------------------------------------------------------- #


@pytest.mark.django_db
def test_htmx_request_returns_fragment_not_full_page(client, setup):
    """An HTMX GET (the active-search form) returns just the results fragment —
    the table for the main swap, no page chrome (no <form>, no <h1>, no doctype)."""
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), HTTP_HX_REQUEST="true")
    assert r.status_code == 200
    body = r.content.decode()
    assert '<table class="advisories"' in body  # the swapped results
    assert "<form" not in body  # no filter form re-rendered
    assert "<h1" not in body
    assert "<!doctype" not in body.lower()


@pytest.mark.django_db
def test_htmx_search_filters_rows(client, setup):
    """The fragment honours ?q just like the full page."""
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), {"q": "smuggling"}, HTTP_HX_REQUEST="true")
    ids = _ids_in_response(r)
    assert ids == {setup["a"].advisory_id}


@pytest.mark.django_db
def test_htmx_fragment_updates_tab_counts_out_of_band(client, setup):
    """The fragment carries the tab strip as an out-of-band swap so the per-state
    counts track the search. ?q=smuggling matches only advisory a (draft)."""
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), {"q": "smuggling"}, HTTP_HX_REQUEST="true")
    body = r.content.decode()
    assert 'id="advisory-state-tabs"' in body
    assert 'hx-swap-oob="true"' in body
    assert 'All<span class="state-tabs__count">1</span>' in body
    assert 'Draft<span class="state-tabs__count">1</span>' in body
    assert 'Published<span class="state-tabs__count">0</span>' in body


@pytest.mark.django_db
def test_full_page_has_search_form(client, setup):
    """The non-HTMX page wires the active-search form (debounced hx-get targeting
    the results)."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list")).content.decode()
    assert 'hx-get="' in body and 'hx-target="#advisory-results"' in body
    assert "delay:300ms" in body
    assert 'id="advisory-results"' in body


@pytest.mark.django_db
def test_full_page_has_persistent_clear_slot(client, setup):
    """The full page always renders the Clear slot (empty when no filter) so the
    active-search fragment has a stable out-of-band target to swap into."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list")).content.decode()
    assert 'id="advisory-filter-clear"' in body
    assert ">Clear<" not in body  # empty slot — no filter active


@pytest.mark.django_db
def test_htmx_search_surfaces_clear_out_of_band(client, setup):
    """Regression: searching live from a state-only view must surface Clear.

    Repro was: on the Dismissed tab (state-only, Clear hidden), typing a query
    filtered the results but never showed Clear — because Clear lived in the
    (un-swapped) form. It's now refreshed out-of-band with the fragment.
    """
    client.force_login(setup["admin"])
    r = client.get(
        reverse("advisories:list"),
        {"state": "dismissed", "q": "smuggling"},
        HTTP_HX_REQUEST="true",
    )
    body = r.content.decode()
    assert 'hx-swap-oob="innerHTML:#advisory-filter-clear"' in body
    assert ">Clear<" in body


@pytest.mark.django_db
def test_htmx_no_filter_removes_clear_out_of_band(client, setup):
    """The inverse: clearing the query during live search empties the Clear slot
    out-of-band (state-only is not a 'filter', so Clear must not show)."""
    client.force_login(setup["admin"])
    r = client.get(
        reverse("advisories:list"),
        {"state": "dismissed"},
        HTTP_HX_REQUEST="true",
    )
    body = r.content.decode()
    assert 'hx-swap-oob="innerHTML:#advisory-filter-clear"' in body  # slot is refreshed
    assert ">Clear<" not in body  # …but emptied


def _clear_href(body: str) -> str | None:
    """The href of the Clear link, or None if it isn't rendered."""
    m = re.search(r'#advisory-filter-clear[^>]*>\s*<a href="([^"]*)">\s*Clear', body, re.S)
    if m:
        return m.group(1)
    m = re.search(r'<a href="([^"]*)">\s*Clear', body)  # OOB fragment (no wrapping span id)
    return m.group(1) if m else None


@pytest.mark.django_db
def test_clear_keeps_state_tab(client, setup):
    """Regression: Clear must drop the search but stay on the current state tab,
    not bounce back to All. State and the search/project filters are separate."""
    client.force_login(setup["admin"])
    body = client.get(
        reverse("advisories:list"), {"state": "dismissed", "q": "smuggling"}
    ).content.decode()
    href = _clear_href(body)
    assert href and "state=dismissed" in href
    assert "q=" not in href


@pytest.mark.django_db
def test_clear_keeps_sort_drops_filter(client, setup):
    """Clear preserves the active sort (ordering is orthogonal to filtering) while
    dropping q."""
    client.force_login(setup["admin"])
    body = client.get(
        reverse("advisories:list"), {"state": "draft", "q": "x", "sort": "project"}
    ).content.decode()
    href = _clear_href(body)
    assert href and "state=draft" in href and "sort=project" in href
    assert "q=x" not in href


@pytest.mark.django_db
def test_clear_on_all_tab_has_no_state(client, setup):
    """On the All tab a search's Clear returns to the bare (All) list — no state."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list"), {"q": "smuggling"}).content.decode()
    href = _clear_href(body)
    assert href is not None
    assert "state=" not in href


@pytest.mark.django_db
def test_htmx_clear_href_keeps_state(client, setup):
    """The out-of-band Clear refreshed during live search carries the same
    state-preserving href."""
    client.force_login(setup["admin"])
    body = client.get(
        reverse("advisories:list"),
        {"state": "dismissed", "q": "smuggling"},
        HTTP_HX_REQUEST="true",
    ).content.decode()
    href = _clear_href(body)
    assert href and "state=dismissed" in href
    assert "q=" not in href


@pytest.mark.django_db
def test_htmx_search_preserves_active_sort_in_pager(client, setup):
    """A live search submitted with the sort hidden field keeps the sort on the
    fragment's pager links (the form echoes ?sort into a hidden input)."""
    client.force_login(setup["admin"])
    r = client.get(
        reverse("advisories:list"),
        {"sort": "state", "page_size": "2"},
        HTTP_HX_REQUEST="true",
    )
    body = r.content.decode()
    m = re.search(r'href="([^"]*page=2[^"]*)"', body)
    assert m, "no Next pager link in fragment"
    assert "sort=state" in m.group(1)


# --------------------------------------------------------------------------- #
# Column sorting
# --------------------------------------------------------------------------- #


def _stamp_modified(setup, order):
    """Set distinct modified_at on the fixture rows (newest first in ``order``).

    ``modified_at`` is auto_now, so it can't be set via create(); QuerySet.update
    bypasses auto_now. Advisory has no append-only trigger (unlike AuditLogEntry),
    so a plain update works on Postgres.
    """
    now = timezone.now()
    for i, key in enumerate(order):
        Advisory.objects.filter(pk=setup[key].pk).update(modified_at=now - timedelta(days=i))


@pytest.mark.django_db
def test_sort_default_is_modified_desc(client, setup):
    """No ?sort → newest-modified first (preserves the historical default)."""
    client.force_login(setup["admin"])
    _stamp_modified(setup, ["a", "b", "c", "d"])  # a newest … d oldest
    order = _ids_in_order(client.get(reverse("advisories:list")))
    assert order == [setup[k].advisory_id for k in ["a", "b", "c", "d"]]


@pytest.mark.django_db
def test_sort_modified_asc(client, setup):
    """?sort=modified reverses the default to oldest-first."""
    client.force_login(setup["admin"])
    _stamp_modified(setup, ["a", "b", "c", "d"])  # a newest … d oldest
    order = _ids_in_order(client.get(reverse("advisories:list"), {"sort": "modified"}))
    assert order == [setup[k].advisory_id for k in ["d", "c", "b", "a"]]


@pytest.mark.django_db
def test_sort_state_ascending_is_lifecycle(client, setup):
    """?sort=state orders triage<draft<published<dismissed, not alphabetically.

    Alphabetical order would put dismissed first and triage last — the reverse —
    so asserting triage leads and dismissed trails pins the lifecycle ranking.
    """
    client.force_login(setup["admin"])
    tri = Advisory.objects.create(project=setup["project_a"], summary="t", state=State.TRIAGE)
    dis = Advisory.objects.create(project=setup["project_a"], summary="x", state=State.DISMISSED)
    order = _ids_in_order(client.get(reverse("advisories:list"), {"sort": "state"}))
    assert order[0] == tri.advisory_id
    assert order[-1] == dis.advisory_id


@pytest.mark.django_db
def test_sort_state_descending(client, setup):
    """?sort=-state reverses the lifecycle ranking."""
    client.force_login(setup["admin"])
    tri = Advisory.objects.create(project=setup["project_a"], summary="t", state=State.TRIAGE)
    dis = Advisory.objects.create(project=setup["project_a"], summary="x", state=State.DISMISSED)
    order = _ids_in_order(client.get(reverse("advisories:list"), {"sort": "-state"}))
    assert order[0] == dis.advisory_id
    assert order[-1] == tri.advisory_id


@pytest.mark.django_db
def test_sort_invalid_falls_back_to_default(client, setup):
    """Unknown / non-sortable sort keys don't blow up — they fall back to default.

    ``summary`` is deliberately not sortable, so it falls back too.
    """
    client.force_login(setup["admin"])
    _stamp_modified(setup, ["a", "b", "c", "d"])
    default = _ids_in_order(client.get(reverse("advisories:list")))
    for bad in ["bogus", "-nonsense", "summary"]:
        r = client.get(reverse("advisories:list"), {"sort": bad})
        assert r.status_code == 200
        assert _ids_in_order(r) == default


@pytest.mark.django_db
def test_sort_persists_across_pagination(client, setup):
    """The Next pager link carries the active sort and advances the page."""
    client.force_login(setup["admin"])
    body = client.get(
        reverse("advisories:list"), {"sort": "state", "page_size": "2"}
    ).content.decode()
    m = re.search(r'href="([^"]*page=2[^"]*)"', body)
    assert m, "no Next pager link found"
    assert "sort=state" in m.group(1)


@pytest.mark.django_db
def test_sort_persists_across_state_tabs(client, setup):
    """State-tab links carry the active sort and reset paging."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list"), {"sort": "modified"}).content.decode()
    m = re.search(r'href="([^"]*state=draft[^"]*)"', body)
    assert m, "no Draft tab href found"
    href = m.group(1)
    assert "sort=modified" in href
    assert "page=" not in href


@pytest.mark.django_db
def test_sort_header_marks_active_column(client, setup):
    """The sorted column's <th> carries aria-sort and its link is .is-active;
    the other four sortable headers are aria-sort="none" (Summary has none)."""
    client.force_login(setup["admin"])

    body = client.get(reverse("advisories:list"), {"sort": "state"}).content.decode()
    assert body.count('aria-sort="ascending"') == 1
    assert body.count('aria-sort="descending"') == 0
    assert body.count('aria-sort="none"') == 4
    active = re.search(r'<a[^>]*class="sort is-active[^"]*"[^>]*>(.*?)</a>', body, re.S)
    assert active and "State" in active.group(1)

    body = client.get(reverse("advisories:list"), {"sort": "-state"}).content.decode()
    assert body.count('aria-sort="descending"') == 1
    assert "sort--desc" in body


@pytest.mark.django_db
def test_sort_active_header_link_toggles(client, setup):
    """Clicking the active column flips its direction (asc⇄desc)."""
    client.force_login(setup["admin"])

    body = client.get(reverse("advisories:list"), {"sort": "modified"}).content.decode()
    link = re.search(r'<a href="([^"]*)" class="sort is-active[^"]*">\s*Modified', body)
    assert link and "sort=-modified" in link.group(1)

    body = client.get(reverse("advisories:list"), {"sort": "-modified"}).content.decode()
    link = re.search(r'<a href="([^"]*)" class="sort is-active[^"]*">\s*Modified', body)
    assert link and "sort=modified" in link.group(1)
    assert "sort=-modified" not in link.group(1)


@pytest.mark.django_db
def test_sort_inactive_header_uses_natural_default(client, setup):
    """An inactive header links to its natural direction (State → ascending),
    not 'always asc' nor the active column's current direction."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list")).content.decode()  # default: modified desc
    state_link = re.search(r'<a href="([^"]*)" class="sort[^"]*">\s*State', body)
    assert state_link and "sort=state" in state_link.group(1)
    assert "sort=-state" not in state_link.group(1)


@pytest.mark.django_db
def test_sort_pagination_is_deterministic(client, setup, make_project):
    """Low-cardinality sorts paginate without dups/skips, via the pk tiebreaker.

    Five same-state rows in a dedicated project; with the project filter only
    those are visible, so three page_size=2 pages must partition them exactly.
    """
    client.force_login(setup["admin"])
    proj = make_project("sortdup")
    made = [
        Advisory.objects.create(project=proj, summary=f"dup-{i}", state=State.DRAFT)
        for i in range(5)
    ]
    expected = {a.advisory_id for a in made}
    seen: list[str] = []
    for page in (1, 2, 3):
        r = client.get(
            reverse("advisories:list"),
            {"sort": "state", "project": str(proj.id), "page_size": "2", "page": str(page)},
        )
        seen.extend(_ids_in_order(r))
    assert len(seen) == len(set(seen)) == 5  # no row duplicated or skipped
    assert set(seen) == expected


# --------------------------------------------------------------------------- #
# Severity filter + sort
# --------------------------------------------------------------------------- #

# Scores pinned by advisories/tests/test_cvss_display.py.
_CVSS_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 critical
_CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5 high


@pytest.fixture
def sev(setup):
    """One advisory per stored severity level, all in project_a (drafts).

    CVSS vectors cover the scored levels; Ubuntu words give unambiguous
    medium/low without hand-computing CVSS. The five fixture rows from ``setup``
    all have empty severity (level ``none``), so a ``?severity=<level>`` query
    that isn't ``none`` returns only the matching row here.
    """
    p = setup["project_a"]
    mk = lambda summary, severity=None: Advisory.objects.create(  # noqa: E731
        project=p, summary=summary, severity=severity or []
    )
    return {
        "crit": mk("sev-crit", [{"type": "CVSS_V3", "score": _CVSS_CRIT}]),
        "high": mk("sev-high", [{"type": "CVSS_V3", "score": _CVSS_HIGH}]),
        "med": mk("sev-med", [{"type": "Ubuntu", "score": "medium"}]),
        "low": mk("sev-low", [{"type": "Ubuntu", "score": "low"}]),
        "unscored": mk("sev-unscored"),
    }


@pytest.mark.django_db
def test_list_renders_severity_column_and_dropdown(client, setup, sev):
    """The list shows a sortable Severity column (replacing Review) and a
    severity filter dropdown; a scored row badges its numeric base score."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list")).content.decode()
    assert re.search(r"<a [^>]*>\s*Severity\s*</a>", body)  # sortable header
    assert ">Review<" not in body  # the old column is gone
    assert '<select name="severity"' in body
    assert ">All severities<" in body
    assert 'class="badge sev-level-critical"' in body  # the crit row's badge
    assert ">9.8<" in body  # its numeric base score


@pytest.mark.django_db
def test_filter_by_severity_exact_level(client, setup, sev):
    client.force_login(setup["admin"])
    ids = _ids_in_response(client.get(reverse("advisories:list"), {"severity": "critical"}))
    assert sev["crit"].advisory_id in ids
    assert sev["high"].advisory_id not in ids
    assert sev["unscored"].advisory_id not in ids


@pytest.mark.django_db
def test_filter_by_severity_unscored(client, setup, sev):
    client.force_login(setup["admin"])
    ids = _ids_in_response(client.get(reverse("advisories:list"), {"severity": "none"}))
    assert sev["unscored"].advisory_id in ids
    assert sev["crit"].advisory_id not in ids
    assert sev["med"].advisory_id not in ids


@pytest.mark.django_db
def test_invalid_severity_silently_ignored(client, setup, sev):
    """An unknown severity value isn't applied — every row stays visible."""
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:list"), {"severity": "spicy"})
    assert r.status_code == 200
    ids = _ids_in_response(r)
    assert sev["crit"].advisory_id in ids
    assert sev["unscored"].advisory_id in ids


@pytest.mark.django_db
def test_severity_filter_narrows_state_tab_counts(client, setup, sev):
    """The severity filter is applied before the per-tab counts, so the tabs
    track it (only the one critical draft matches)."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list"), {"severity": "critical"}).content.decode()
    assert 'All<span class="state-tabs__count">1</span>' in body
    assert 'Draft<span class="state-tabs__count">1</span>' in body
    assert 'Published<span class="state-tabs__count">0</span>' in body


@pytest.mark.django_db
def test_severity_filter_clear_drops_it_keeps_state(client, setup, sev):
    """Severity is a search/project-class filter: it surfaces Clear, and Clear
    drops it while keeping the active state tab."""
    client.force_login(setup["admin"])
    body = client.get(
        reverse("advisories:list"), {"state": "draft", "severity": "critical"}
    ).content.decode()
    href = _clear_href(body)
    assert href and "state=draft" in href
    assert "severity=" not in href


@pytest.mark.django_db
def test_severity_header_natural_default_is_desc(client, setup):
    """The Severity column sorts worst-first on first click (default_desc)."""
    client.force_login(setup["admin"])
    body = client.get(reverse("advisories:list")).content.decode()
    m = re.search(r'<a href="([^"]*)" class="sort[^"]*">\s*Severity', body)
    assert m and "sort=-severity" in m.group(1)
    assert "sort=severity&" not in m.group(1) and not m.group(1).endswith("sort=severity")


@pytest.mark.django_db
def test_sort_by_severity_worst_first(client, setup, sev):
    """?sort=-severity ranks critical > high > medium > low > unscored."""
    client.force_login(setup["admin"])
    order = _ids_in_order(client.get(reverse("advisories:list"), {"sort": "-severity"}))
    ranked = [sev[k].advisory_id for k in ("crit", "high", "med", "low")]
    positions = [order.index(i) for i in ranked]
    assert positions == sorted(positions)
    # The unscored row trails all scored ones.
    assert order.index(sev["unscored"].advisory_id) > positions[-1]


@pytest.mark.django_db
def test_sort_by_severity_ascending_reverses(client, setup, sev):
    """?sort=severity (ascending) puts the least-severe scored row ahead of the
    most-severe one."""
    client.force_login(setup["admin"])
    order = _ids_in_order(client.get(reverse("advisories:list"), {"sort": "severity"}))
    assert order.index(sev["low"].advisory_id) < order.index(sev["crit"].advisory_id)
