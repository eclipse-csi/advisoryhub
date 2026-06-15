"""DB-backed tests for the admin Stats page: the ORM sample fetchers,
the promote-then-dismiss semantics, and the view (access + rendering)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from admin_console.stats import (
    fetch_reverted_samples,
    fetch_ttfr_samples,
    fetch_ttp_samples,
)
from advisories.models import Advisory, AdvisoryIntakeMetadata, State
from audit.models import Action, AuditLogEntry
from audit.retention import _audit_trigger_bypass
from audit.services import record


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    return {"admin": admin, "member": member, "project": project}


# ----- builders ----------------------------------------------------------


def _publish(project, by, *, created, published):
    adv = Advisory.objects.create(
        project=project, summary="pub", created_by=by, state=State.PUBLISHED
    )
    Advisory.objects.filter(pk=adv.pk).update(created_at=created, published_at=published)
    return adv


def _intake(project, by, *, submitted, state=State.TRIAGE):
    adv = Advisory.objects.create(project=project, summary="report", created_by=by, state=state)
    AdvisoryIntakeMetadata.objects.create(advisory=adv)
    Advisory.objects.filter(pk=adv.pk).update(created_at=submitted)
    AdvisoryIntakeMetadata.objects.filter(advisory=adv).update(submitted_at=submitted)
    return adv


def _event(adv, action, when, *, by):
    entry = record(action=action, actor=by, advisory=adv, metadata={"advisory_id": adv.advisory_id})
    with _audit_trigger_bypass():
        AuditLogEntry.objects.filter(pk=entry.pk).update(created_at=when)
    return entry


# ----- TTP ---------------------------------------------------------------


@pytest.mark.django_db
def test_ttp_samples_duration_and_anchor(setup):
    now = timezone.now()
    created, published = now - timedelta(days=3), now - timedelta(days=1)
    _publish(setup["project"], setup["admin"], created=created, published=published)
    samples = fetch_ttp_samples()
    assert len(samples) == 1
    anchor, dur = samples[0]
    assert dur == pytest.approx((published - created).total_seconds())
    assert abs((anchor - published).total_seconds()) < 1


@pytest.mark.django_db
def test_ttp_excludes_unpublished_and_null_published_at(setup):
    # Draft advisory + a PUBLISHED row whose published_at was never set.
    Advisory.objects.create(project=setup["project"], summary="d", created_by=setup["admin"])
    Advisory.objects.create(
        project=setup["project"], summary="p", created_by=setup["admin"], state=State.PUBLISHED
    )
    assert fetch_ttp_samples() == []


# ----- TTFR --------------------------------------------------------------


@pytest.mark.django_db
def test_ttfr_uses_earliest_qualifying_action(setup):
    now = timezone.now()
    submitted = now - timedelta(days=10)
    adv = _intake(setup["project"], setup["admin"], submitted=submitted)
    promoted = now - timedelta(days=8)
    _event(adv, Action.ADVISORY_TRIAGE_PROMOTED, promoted, by=setup["admin"])
    _event(adv, Action.ADVISORY_DISMISSED, now - timedelta(days=6), by=setup["admin"])
    samples = fetch_ttfr_samples()
    assert len(samples) == 1
    anchor, dur = samples[0]
    # First response is the (earlier) promotion, not the later dismissal.
    assert dur == pytest.approx((promoted - submitted).total_seconds())
    assert abs((anchor - promoted).total_seconds()) < 1


@pytest.mark.django_db
def test_ttfr_excludes_unanswered_and_non_intake(setup):
    now = timezone.now()
    # Intake report with no first-response action → no completion → no sample.
    _intake(setup["project"], setup["admin"], submitted=now - timedelta(days=2))
    # Non-intake advisory (no sidecar) with a promotion → out of TTFR scope.
    other = Advisory.objects.create(
        project=setup["project"], summary="x", created_by=setup["admin"]
    )
    _event(other, Action.ADVISORY_TRIAGE_PROMOTED, now - timedelta(days=1), by=setup["admin"])
    assert fetch_ttfr_samples() == []


@pytest.mark.django_db
def test_ttfr_ignores_actions_outside_the_first_response_set(setup):
    now = timezone.now()
    adv = _intake(setup["project"], setup["admin"], submitted=now - timedelta(days=3))
    # An edit is not a "first response"; it must not anchor TTFR.
    _event(adv, Action.ADVISORY_EDITED, now - timedelta(days=2), by=setup["admin"])
    assert fetch_ttfr_samples() == []


# ----- Reverted (promote-then-dismiss) ----------------------------------


@pytest.mark.django_db
def test_reverted_counts_promote_then_dismiss_and_feeds_ttfr(setup):
    now = timezone.now()
    submitted = now - timedelta(days=12)
    adv = _intake(setup["project"], setup["admin"], submitted=submitted, state=State.DISMISSED)
    promoted = now - timedelta(days=10)
    dismissed = now - timedelta(days=6)
    _event(adv, Action.ADVISORY_TRIAGE_PROMOTED, promoted, by=setup["admin"])
    _event(adv, Action.ADVISORY_DISMISSED, dismissed, by=setup["admin"])

    reverted = fetch_reverted_samples()
    assert len(reverted) == 1
    assert abs((reverted[0][0] - dismissed).total_seconds()) < 1  # anchored on dismissal

    # The same report still produces a TTFR sample, anchored on the promotion.
    ttfr = fetch_ttfr_samples()
    assert len(ttfr) == 1
    assert ttfr[0][1] == pytest.approx((promoted - submitted).total_seconds())


@pytest.mark.django_db
def test_reverted_excludes_direct_triage_dismissal(setup):
    now = timezone.now()
    adv = _intake(setup["project"], setup["admin"], submitted=now - timedelta(days=5))
    # Dismissed straight from triage — never promoted → not a reversion.
    _event(adv, Action.ADVISORY_DISMISSED, now - timedelta(days=4), by=setup["admin"])
    assert fetch_reverted_samples() == []
    # ...but it is still a (dismissal) first response for TTFR.
    assert len(fetch_ttfr_samples()) == 1


# ----- View --------------------------------------------------------------


@pytest.mark.django_db
def test_stats_view_403_for_non_admin(client, setup):
    client.force_login(setup["member"])
    assert client.get(reverse("admin_console:stats")).status_code == 403


@pytest.mark.django_db
def test_stats_view_renders_both_metrics(client, setup):
    client.force_login(setup["admin"])
    resp = client.get(reverse("admin_console:stats"))
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "Time to first response" in body
    assert "Time to publish" in body
    assert "Reverted" in body


@pytest.mark.django_db
def test_stats_view_custom_range_adds_a_row(client, setup):
    client.force_login(setup["admin"])
    today = timezone.now().date()
    start = (today - timedelta(days=30)).isoformat()
    end = today.isoformat()
    resp = client.get(reverse("admin_console:stats") + f"?start={start}&end={end}")
    assert resp.status_code == 200
    assert resp.context["has_custom_range"] is True
    assert "Custom range" in resp.content.decode()
    assert resp.context["ttp_rows"][-1].period_key == "custom"


@pytest.mark.django_db
def test_stats_view_ignores_invalid_custom_range(client, setup):
    client.force_login(setup["admin"])
    today = timezone.now().date()
    # start after end, and a single-bound range — both ignored gracefully.
    bad = f"?start={today.isoformat()}&end={(today - timedelta(days=5)).isoformat()}"
    resp = client.get(reverse("admin_console:stats") + bad)
    assert resp.status_code == 200
    assert resp.context["has_custom_range"] is False
    only_one = client.get(reverse("admin_console:stats") + f"?start={today.isoformat()}")
    assert only_one.context["has_custom_range"] is False


# ----- Trend sparkline (SVG) ---------------------------------------------


@pytest.mark.django_db
def test_stats_view_renders_sparkline_when_data_present(client, setup):
    now = timezone.now()
    # One published advisory in the last 12 months → TTP sparkline has data.
    _publish(
        setup["project"],
        setup["admin"],
        created=now - timedelta(days=40),
        published=now - timedelta(days=10),
    )
    # One answered intake report → TTFR sparkline has data.
    adv = _intake(setup["project"], setup["admin"], submitted=now - timedelta(days=20))
    _event(adv, Action.ADVISORY_TRIAGE_PROMOTED, now - timedelta(days=19), by=setup["admin"])
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:stats")).content.decode()
    assert 'class="sparkline"' in body
    assert "<polyline" in body
    # Axis scaffold + current-value readout render alongside the line.
    assert "stats-chart__yaxis" in body
    assert "stats-chart__xaxis" in body
    assert "now: mean" in body


@pytest.mark.django_db
def test_stats_view_sparkline_empty_state(client, setup):
    # No published / intake advisories at all → both sparklines show the
    # placeholder instead of an empty chart.
    client.force_login(setup["admin"])
    body = client.get(reverse("admin_console:stats")).content.decode()
    assert "No data in the last 12 months." in body
    assert "<polyline" not in body
    assert "stats-chart__yaxis" not in body  # no axis scaffold without data


# ----- Per-project filter ------------------------------------------------


@pytest.mark.django_db
def test_fetch_samples_scoped_by_project(setup, make_project):
    now = timezone.now()
    other = make_project("q")
    _publish(
        setup["project"],
        setup["admin"],
        created=now - timedelta(days=5),
        published=now - timedelta(days=1),
    )
    _publish(
        other, setup["admin"], created=now - timedelta(days=6), published=now - timedelta(days=2)
    )
    assert len(fetch_ttp_samples()) == 2  # unscoped → both projects
    assert len(fetch_ttp_samples(project_slug="p")) == 1
    assert len(fetch_ttp_samples(project_slug="q")) == 1
    assert fetch_ttp_samples(project_slug="does-not-exist") == []


@pytest.mark.django_db
def test_stats_view_project_filter_scopes_and_renders_dropdown(client, setup, make_project):
    now = timezone.now()
    make_project("q")
    _publish(
        setup["project"],
        setup["admin"],
        created=now - timedelta(days=5),
        published=now - timedelta(days=1),
    )
    client.force_login(setup["admin"])
    resp = client.get(reverse("admin_console:stats") + "?project=p")
    assert resp.status_code == 200
    assert resp.context["selected_project"] == "p"
    body = resp.content.decode()
    assert '<select name="project"' in body
    assert 'value="p"' in body  # the project option is offered
    # all-time TTP (last predefined period, no custom range) sees only project p.
    assert resp.context["ttp_rows"][-1].current.count == 1


@pytest.mark.django_db
def test_stats_view_bogus_project_is_ignored(client, setup):
    client.force_login(setup["admin"])
    resp = client.get(reverse("admin_console:stats") + "?project=nope")
    assert resp.status_code == 200
    assert resp.context["selected_project"] == ""
