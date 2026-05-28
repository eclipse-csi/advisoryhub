"""End-to-end coverage for the AdvisoryVersion edit-history feature.

The lower-level model and helper behaviour is exercised in test_models.py
(immutability, append helper, if_changed semantics). This module focuses
on the higher-level invariants observable from views and workflows:

* Editing through the form appends a version.
* Workflow-only saves (publish, dismiss, GHSA timestamp heartbeat) don't.
* The history endpoint enforces permissions and returns the right rows.
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from advisories.models import Advisory, AdvisoryVersion, State

_FORMSET_SECTIONS = ("aliases", "cwe_ids", "references", "severity", "credits", "affected")


def _empty_formset_payload() -> dict[str, str]:
    payload: dict[str, str] = {}
    for prefix in _FORMSET_SECTIONS:
        payload[f"{prefix}-TOTAL_FORMS"] = "0"
        payload[f"{prefix}-INITIAL_FORMS"] = "0"
        payload[f"{prefix}-MIN_NUM_FORMS"] = "0"
        payload[f"{prefix}-MAX_NUM_FORMS"] = "1000"
    return payload


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    outsider = make_user(email="o@example.org")
    project = make_project("eclipse-jetty", team_members=[member], is_mature_publisher=True)
    advisory = Advisory.objects.create(
        project=project,
        summary="initial summary",
        details="initial details",
        created_by=member,
    )
    return {
        "admin": admin,
        "member": member,
        "outsider": outsider,
        "project": project,
        "advisory": advisory,
    }


# ---- v1 invariant ---------------------------------------------------------


@pytest.mark.django_db
def test_v1_seeded_at_creation_via_signal(setup):
    versions = list(setup["advisory"].versions.order_by("version"))
    assert [v.version for v in versions] == [1]
    assert versions[0].payload["summary"] == "initial summary"
    assert versions[0].editor == setup["member"]


# ---- Edit view appends a version -----------------------------------------


@pytest.mark.django_db
def test_edit_view_appends_v2(client, setup):
    client.force_login(setup["member"])
    payload = {
        "project": setup["project"].pk,
        "summary": "edited summary",
        "details": "edited details",
    }
    payload.update(_empty_formset_payload())

    response = client.post(
        reverse("advisories:edit", args=[setup["advisory"].advisory_id]),
        data=payload,
    )
    assert response.status_code == 302

    versions = list(setup["advisory"].versions.order_by("version"))
    assert [v.version for v in versions] == [1, 2]
    assert versions[1].payload["summary"] == "edited summary"
    assert versions[1].editor == setup["member"]


# ---- No version churn on workflow-only saves -----------------------------


@pytest.mark.django_db
def test_state_flip_does_not_append_version(setup):
    advisory = setup["advisory"]
    advisory.state = State.PUBLISHED
    advisory.save(update_fields=["state", "modified_at"])
    assert advisory.versions.count() == 1


@pytest.mark.django_db
def test_republish_required_flag_does_not_append_version(setup):
    advisory = setup["advisory"]
    advisory.republish_required = True
    advisory.save(update_fields=["republish_required", "modified_at"])
    assert advisory.versions.count() == 1


# ---- History endpoint ----------------------------------------------------


@pytest.mark.django_db
def test_history_endpoint_returns_versions_for_member(client, setup):
    client.force_login(setup["member"])
    response = client.get(reverse("advisories:history", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 200
    assert b"v1" in response.content


@pytest.mark.django_db
def test_history_endpoint_403_for_outsider(client, setup):
    client.force_login(setup["outsider"])
    response = client.get(reverse("advisories:history", args=[setup["advisory"].advisory_id]))
    assert response.status_code == 403


# ---- if_changed semantics on services ------------------------------------


@pytest.mark.django_db
def test_reassign_triage_appends_version_on_project_change(setup, make_project):
    """Triage reassignment changes project_slug — payload-visible, so a new
    version is appended.
    """
    from advisories import services as adv_services

    triage = Advisory.objects.create(
        project=setup["project"],
        state=State.TRIAGE,
        summary="from triage",
        created_by=setup["member"],
    )
    other = make_project("other", team_members=[setup["admin"]])
    initial_versions = list(triage.versions.order_by("version"))
    assert [v.version for v in initial_versions] == [1]

    adv_services.reassign_triage_project(triage, by=setup["admin"], new_project=other)

    versions = list(triage.versions.order_by("version"))
    assert [v.version for v in versions] == [1, 2]
    assert versions[1].payload["project_slug"] == "other"


# ---- model-level cross-cutting checks ------------------------------------


@pytest.mark.django_db
def test_advisory_version_obj_count_matches_advisories(setup):
    """Sanity: every Advisory should always have at least one version."""
    advisories = Advisory.objects.count()
    advisories_with_v1 = (
        AdvisoryVersion.objects.filter(version=1).values("advisory_id").distinct().count()
    )
    assert advisories == advisories_with_v1
