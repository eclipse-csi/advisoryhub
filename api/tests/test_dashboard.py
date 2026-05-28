from __future__ import annotations

import json

import pytest
from django.urls import reverse

from advisories.models import Advisory, ReviewStatus
from workflows import services as wf
from workflows.models import CveRequestStatus, ReviewTaskStatus


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x", created_by=member)
    return {"admin": admin, "member": member, "advisory": advisory}


@pytest.mark.django_db
def test_cve_transition_requires_admin(client, setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:cve_transition", args=[task.pk]),
        data=json.dumps({"status": CveRequestStatus.RESERVED, "cve_id": "CVE-2026-1111"}),
        content_type="application/json",
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_cve_transition_queued_to_reserved(client, setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("api:cve_transition", args=[task.pk]),
        data=json.dumps({"status": CveRequestStatus.RESERVED, "cve_id": "CVE-2026-1111"}),
        content_type="application/json",
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == CveRequestStatus.RESERVED
    assert body["cve_id"] == "CVE-2026-1111"


@pytest.mark.django_db
def test_cve_transition_invalid_status_returns_400(client, setup):
    task = wf.request_cve(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("api:cve_transition", args=[task.pk]),
        data=json.dumps({"status": "lost"}),
        content_type="application/json",
    )
    assert response.status_code == 400


@pytest.mark.django_db
def test_review_decide_approve(client, setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["member"])
    client.force_login(setup["admin"])
    response = client.post(
        reverse("api:review_decide", args=[task.pk]),
        data=json.dumps({"decision": ReviewTaskStatus.APPROVED, "notes": "lgtm"}),
        content_type="application/json",
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == ReviewTaskStatus.APPROVED
    setup["advisory"].refresh_from_db()
    assert setup["advisory"].review_status == ReviewStatus.APPROVED


@pytest.mark.django_db
def test_review_decide_blocked_for_member(client, setup):
    task = wf.submit_for_review(setup["advisory"], by=setup["member"])
    client.force_login(setup["member"])
    response = client.post(
        reverse("api:review_decide", args=[task.pk]),
        data=json.dumps({"decision": ReviewTaskStatus.APPROVED}),
        content_type="application/json",
    )
    assert response.status_code == 403
