"""Integration tests for uniform action feedback (Django messages → toasts).

Asserts the per-view ``messages.*`` wiring: success on full-page actions, the
``unassign_cve`` ValueError→error guard, a hard 403 staying silent, and that a
full-page redirect's message surfaces through the ``#toast-data`` island on the
next load. The HX-Trigger serialisation itself is unit-tested in
``common/test_toast_messages.py``.
"""

from __future__ import annotations

import pytest
from django.contrib.messages import get_messages
from django.urls import reverse

from advisories.models import Advisory, AdvisoryIntakeMetadata, State


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    outsider = make_user(email="o@example.org")
    project = make_project("alpha", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x", created_by=member)
    return {
        "admin": admin,
        "member": member,
        "outsider": outsider,
        "project": project,
        "advisory": advisory,
    }


def _tags(response):
    return [(m.level_tag, str(m)) for m in get_messages(response.wsgi_request)]


def _dismiss(advisory):
    advisory.state = State.DISMISSED
    advisory.dismissed_reason = "duplicate"
    advisory.dismissed_from_state = State.DRAFT
    advisory.save()
    return advisory


def _triage_advisory(project):
    advisory = Advisory.objects.create(project=project, state=State.TRIAGE, summary="t")
    AdvisoryIntakeMetadata.objects.create(advisory=advisory)
    return advisory


@pytest.mark.django_db
def test_reopen_emits_success_message(setup, client):
    advisory = _dismiss(setup["advisory"])
    client.force_login(setup["member"])
    resp = client.post(reverse("advisories:reopen", args=[advisory.advisory_id]))
    assert resp.status_code == 302
    assert ("success", "Advisory reopened.") in _tags(resp)


@pytest.mark.django_db
def test_full_page_message_renders_in_island(setup, client):
    advisory = _dismiss(setup["advisory"])
    client.force_login(setup["member"])
    resp = client.post(reverse("advisories:reopen", args=[advisory.advisory_id]), follow=True)
    assert resp.status_code == 200
    body = resp.content.decode()
    assert 'id="toast-data"' in body
    assert "Advisory reopened." in body


@pytest.mark.django_db
def test_submit_review_forbidden_emits_no_message(setup, client):
    # A hard 403 (PermissionDenied) surfaces via the client transport-error
    # toast, not a server message — so storage must stay empty.
    client.force_login(setup["outsider"])
    resp = client.post(reverse("advisories:submit_review", args=[setup["advisory"].advisory_id]))
    assert resp.status_code == 403
    assert _tags(resp) == []


@pytest.mark.django_db
def test_unassign_cve_without_cve_shows_error_not_500(setup, client):
    # Draft advisory with no assigned CVE — the service raises ValueError; the
    # view turns it into a persistent error message + redirect (never a 500).
    client.force_login(setup["admin"])
    resp = client.post(reverse("advisories:unassign_cve", args=[setup["advisory"].advisory_id]))
    assert resp.status_code == 302
    assert "error" in [level for level, _ in _tags(resp)]


@pytest.mark.django_db
def test_flag_htmx_survives_refresh_to_island(setup, client):
    advisory = _triage_advisory(setup["project"])
    client.force_login(setup["member"])
    resp = client.post(
        reverse("advisories:flag", args=[advisory.advisory_id]),
        {"note": "belongs in bravo"},
        HTTP_HX_REQUEST="true",
    )
    assert resp.status_code == 204
    assert resp["HX-Refresh"] == "true"
    # Not consumed on the refresh response, so the reloaded page's island shows it.
    assert "HX-Trigger" not in resp
    detail = client.get(reverse("advisories:detail", args=[advisory.advisory_id]))
    assert "Flagged for admin routing." in detail.content.decode()
