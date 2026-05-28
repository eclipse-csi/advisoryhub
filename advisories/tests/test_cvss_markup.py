"""Smoke test: edit-advisory page exposes the CVSS calculator markup."""

import pytest
from django.urls import reverse

from advisories.models import Advisory


@pytest.fixture
def admin_user(make_user, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    return make_user(email="admin@example.org", groups=["advisoryhub-security"])


@pytest.fixture
def project_a(make_project):
    return make_project("project-a")


@pytest.mark.django_db
def test_edit_page_includes_cvss_calculator(client, admin_user, project_a):
    advisory = Advisory.objects.create(
        project=project_a,
        summary="x",
        state="draft",
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    )
    client.force_login(admin_user)
    response = client.get(reverse("advisories:edit", args=[advisory.advisory_id]))
    assert response.status_code == 200
    html = response.content.decode()
    assert "data-cvss-calculator" in html, "calculator details element missing"
    assert "data-cvss-score" in html, "score badge missing"
    assert "advisoryhub-cvss.js" in html, "calculator JS not included on page"
    assert "CVSS calculator" in html, "calculator summary text missing"
