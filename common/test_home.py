from __future__ import annotations

import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_home_anonymous_renders_branded_landing(client):
    """Anonymous visitors get the branded sign-in landing, not a bare bounce."""
    response = client.get("/")
    assert response.status_code == 200
    content = response.content
    assert b"AdvisoryHub" in content
    # Sign-in CTA points at the OIDC init, and the public intake link is offered.
    assert reverse("oidc_authentication_init").encode() in content
    assert reverse("intake:report").encode() in content


@pytest.mark.django_db
def test_home_authenticated_redirects_to_advisory_list(client, make_user):
    """Signed-in users skip the landing and go straight to their working list."""
    client.force_login(make_user(email="u@example.org"))
    response = client.get("/")
    assert response.status_code == 302
    assert response.url == reverse("advisories:list")
