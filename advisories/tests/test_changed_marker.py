"""Tests for the "Changed since last visit" / "New" markers.

The signal compares a viewer's ``AdvisoryVisit`` against the newest durable
``AuditLogEntry`` for the advisory, excluding the viewer's own actions. Plain
views land in the ephemeral ``AccessLogEntry`` and must not count.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from advisories.models import Advisory, AdvisoryVisit
from advisories.visit_markers import annotate_visit_markers, set_visit_markers
from audit.models import Action, AuditLogEntry
from audit.services import record


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    viewer = make_user(email="v@example.org")
    actor = make_user(email="a@example.org")
    project = make_project("p", team_members=[viewer, actor])
    advisory = Advisory.objects.create(project=project, summary="x")
    return {"viewer": viewer, "actor": actor, "project": project, "advisory": advisory}


def _marker(user, advisory):
    rows = list(annotate_visit_markers(Advisory.objects.filter(pk=advisory.pk), user))
    set_visit_markers(rows)
    return rows[0].changed_marker


def _visit(user, advisory, *, at=None):
    AdvisoryVisit.objects.update_or_create(
        user=user, advisory=advisory, defaults={"last_visited_at": at or timezone.now()}
    )


# ---- the core signal (helper-level, timestamp-robust) ---------------------


@pytest.mark.django_db
def test_never_visited_is_new(setup):
    assert _marker(setup["viewer"], setup["advisory"]) == "new"


@pytest.mark.django_db
def test_activity_after_visit_is_changed(setup):
    _visit(setup["viewer"], setup["advisory"], at=timezone.now() - timedelta(hours=1))
    record(action=Action.ADVISORY_EDITED, actor=setup["actor"], advisory=setup["advisory"])
    assert _marker(setup["viewer"], setup["advisory"]) == "changed"


@pytest.mark.django_db
def test_visit_after_activity_is_not_changed(setup):
    record(action=Action.ADVISORY_EDITED, actor=setup["actor"], advisory=setup["advisory"])
    _visit(setup["viewer"], setup["advisory"], at=timezone.now() + timedelta(hours=1))
    assert _marker(setup["viewer"], setup["advisory"]) == ""


@pytest.mark.django_db
def test_own_actions_do_not_self_mark(setup):
    _visit(setup["viewer"], setup["advisory"], at=timezone.now() - timedelta(hours=1))
    # The viewer's *own* edit must not flip their marker.
    record(action=Action.ADVISORY_EDITED, actor=setup["viewer"], advisory=setup["advisory"])
    assert _marker(setup["viewer"], setup["advisory"]) == ""


@pytest.mark.django_db
def test_views_do_not_count_as_changes(setup):
    _visit(setup["viewer"], setup["advisory"], at=timezone.now() - timedelta(hours=1))
    # A plain view by someone else is ephemeral (AccessLogEntry), never durable.
    record(action=Action.ADVISORY_VIEWED, actor=setup["actor"], advisory=setup["advisory"])
    assert not AuditLogEntry.objects.filter(advisory=setup["advisory"]).exists()
    assert _marker(setup["viewer"], setup["advisory"]) == ""


# ---- end-to-end through the views -----------------------------------------


@pytest.mark.django_db
def test_list_marks_new_then_clears_after_visit(setup, client):
    client.force_login(setup["viewer"])
    detail = reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    listing = reverse("advisories:list")
    assert b"new-since-visit" in client.get(listing).content
    client.get(detail)  # stamps the visit
    assert b"new-since-visit" not in client.get(listing).content


@pytest.mark.django_db
def test_list_marks_changed_after_external_edit(setup, client):
    client.force_login(setup["viewer"])
    detail = reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    listing = reverse("advisories:list")
    client.get(detail)  # visit now
    # Backdate the visit so the subsequent edit is unambiguously "after".
    AdvisoryVisit.objects.filter(user=setup["viewer"], advisory=setup["advisory"]).update(
        last_visited_at=timezone.now() - timedelta(hours=1)
    )
    record(action=Action.ADVISORY_EDITED, actor=setup["actor"], advisory=setup["advisory"])
    body = client.get(listing).content
    assert b"changed-since-visit" in body
    assert b"new-since-visit" not in body


@pytest.mark.django_db
def test_detail_visit_timestamp_advances(setup, client):
    """Guards the ``auto_now`` + explicit-``defaults`` bump: a second visit must
    advance the timestamp (an empty ``defaults`` would leave it stale)."""
    client.force_login(setup["viewer"])
    detail = reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    client.get(detail)
    past = timezone.now() - timedelta(hours=1)
    AdvisoryVisit.objects.filter(user=setup["viewer"], advisory=setup["advisory"]).update(
        last_visited_at=past
    )
    client.get(detail)
    visit = AdvisoryVisit.objects.get(user=setup["viewer"], advisory=setup["advisory"])
    assert visit.last_visited_at > past
