"""Project create/edit form opts into the shared save-feedback JS.

Mirrors the indicator + double-submit-guard wiring added to the other
full-page save forms; also exercises the template's new ``{% load static %}``
+ ``extra_head`` block (which loads ``advisoryhub-form-dirty.js``).
"""

from __future__ import annotations

import pytest
from django.urls import reverse


@pytest.fixture
def admin(make_user, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    return make_user(email="admin@example.org", groups=["advisoryhub-security"])


@pytest.mark.django_db
def test_project_create_form_wires_save_feedback(client, admin):
    client.force_login(admin)
    body = client.get(reverse("admin_console:project_create")).content.decode()
    assert "advisoryhub-form-dirty.js" in body
    assert "data-submit-once" in body
    assert "data-unsaved-indicator" in body
    assert "Unsaved changes" in body
    # No-JS degradation: the Create button must not be disabled server-side.
    assert '<button type="submit">Create</button>' in body
