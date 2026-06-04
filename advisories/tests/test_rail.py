"""Tests for the dense left navigation rail on the detail/edit pages.

The rail is rendered by the ``{% advisory_rail %}`` inclusion tag and must obey
the same server-side visibility rule as the list view (INV-AUTH-1): it can only
ever surface advisories the viewer could already reach.
"""

from __future__ import annotations

import re

import pytest
from django.urls import reverse

from advisories.models import Advisory, ReviewStatus, State


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    member = make_user(email="member@example.org")
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    mine = make_project("mine", team_members=[member])
    other = make_project("other")
    a1 = Advisory.objects.create(project=mine, summary="SQLi in auth module")
    a2 = Advisory.objects.create(
        project=mine, summary="Reflected XSS", review_status=ReviewStatus.SUBMITTED
    )
    published = Advisory.objects.create(
        project=mine, summary="Old published bug", state=State.PUBLISHED
    )
    hidden = Advisory.objects.create(project=other, summary="Not visible to member")
    return {
        "member": member,
        "admin": admin,
        "a1": a1,
        "a2": a2,
        "published": published,
        "hidden": hidden,
    }


@pytest.mark.django_db
def test_rail_lists_visible_advisories_on_detail(client, setup):
    client.force_login(setup["member"])
    r = client.get(reverse("advisories:detail", args=[setup["a1"].advisory_id]))
    body = r.content.decode()
    assert 'class="advisory-rail"' in body
    assert "← All advisories" in body
    # a2 only appears on a1's page via the rail (it is otherwise unrelated).
    assert setup["a2"].advisory_id in body


@pytest.mark.django_db
def test_rail_excludes_inaccessible_advisories(client, setup):
    """An advisory the member cannot reach is absent from the rail (INV-AUTH-1)."""
    client.force_login(setup["member"])
    r = client.get(reverse("advisories:detail", args=[setup["a1"].advisory_id]))
    assert setup["hidden"].advisory_id not in r.content.decode()


@pytest.mark.django_db
def test_rail_marks_current_advisory_active(client, setup):
    client.force_login(setup["member"])
    r = client.get(reverse("advisories:detail", args=[setup["a1"].advisory_id]))
    body = r.content.decode()
    match = re.search(r'class="advisory-rail__item is-active"\s+href="([^"]+)"', body)
    assert match, "current advisory should be flagged is-active in the rail"
    assert match.group(1) == reverse("advisories:detail", args=[setup["a1"].advisory_id])
    assert 'aria-current="page"' in body


@pytest.mark.django_db
def test_rail_present_on_edit_page(client, setup):
    client.force_login(setup["member"])
    r = client.get(reverse("advisories:edit", args=[setup["a1"].advisory_id]))
    body = r.content.decode()
    assert 'class="advisory-rail"' in body
    assert setup["a2"].advisory_id in body


@pytest.mark.django_db
def test_admin_rail_includes_all_advisories(client, setup):
    """Admins see every advisory in the list, so the rail surfaces them too."""
    client.force_login(setup["admin"])
    r = client.get(reverse("advisories:detail", args=[setup["a1"].advisory_id]))
    assert setup["hidden"].advisory_id in r.content.decode()


@pytest.mark.django_db
def test_rail_excludes_published_advisories(client, setup):
    """Published advisories accumulate; the rail keeps the active working set."""
    client.force_login(setup["member"])
    r = client.get(reverse("advisories:detail", args=[setup["a1"].advisory_id]))
    assert setup["published"].advisory_id not in r.content.decode()


@pytest.mark.django_db
def test_rail_pins_current_advisory_even_when_published(client, setup):
    """The advisory being viewed is always shown + active, even if published."""
    client.force_login(setup["member"])
    pub = setup["published"]
    r = client.get(reverse("advisories:detail", args=[pub.advisory_id]))
    body = r.content.decode()
    match = re.search(r'class="advisory-rail__item is-active"\s+href="([^"]+)"', body)
    assert match, "current published advisory should be pinned + active in the rail"
    assert match.group(1) == reverse("advisories:detail", args=[pub.advisory_id])


@pytest.mark.django_db
def test_rail_truncates_with_more_link(client, setup, monkeypatch):
    monkeypatch.setattr("advisories.templatetags.advisory_display._RAIL_LIMIT", 1)
    client.force_login(setup["member"])
    r = client.get(reverse("advisories:detail", args=[setup["a1"].advisory_id]))
    body = r.content.decode()
    # member can see a1 + a2 → with a cap of 1, one row is dropped behind a link.
    assert "more in the full list" in body
