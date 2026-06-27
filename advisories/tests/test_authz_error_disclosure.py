"""Regression tests: validation-error re-render must not disclose content (INV-AUTH-1).

Four POST handlers used to reach ``_detail_with_error`` — which re-renders the
full ``advisories/detail.html`` (summary, the embargoed ``details`` write-up,
project, CVE, intake sidecar) — on an input-validation failure path *before* any
authorization check. An authenticated outsider who knew an advisory's
``advisory_id`` could read its confidential content as a 400 body regardless of
role, project membership, or grant (report ``advisoryhub--004``).

These tests assert the fix: an outsider hitting each validation-error path now
gets ``403`` and the secret content never appears in the body. The
authorized-user error paths (admin posting a bad/duplicate slug → 400 with
content) are covered by ``test_draft_reassignment.py`` / ``test_triage.py`` and
must stay green.
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from advisories import permissions as perms
from advisories.models import Advisory, AdvisoryIntakeMetadata, State

SECRET_SUMMARY = "EMBARGOED RCE in widget parser"
SECRET_DETAILS = "Heap overflow at parse_chunk(); patch lands 2026-07-15."


@pytest.fixture
def outsider(db, make_user):
    """An authenticated user with no grant on any advisory and on no security
    team — e.g. a freshly OIDC-onboarded account."""
    return make_user(email="mallory@example.org")


@pytest.fixture
def draft_advisory(db, make_project, make_user):
    """A draft advisory the outsider has no relationship to."""
    owner = make_user(email="owner@example.org")
    project = make_project(name="technology.victim", team_members=[owner])
    return Advisory.objects.create(
        project=project,
        summary=SECRET_SUMMARY,
        details=SECRET_DETAILS,
        state=State.DRAFT,
        created_by=owner,
    )


@pytest.fixture
def triage_advisory(db, make_project, make_user):
    """A triage advisory (flagged for routing) the outsider has no access to."""
    owner = make_user(email="owner3@example.org")
    project = make_project(name="technology.triage", team_members=[owner])
    adv = Advisory.objects.create(
        project=project,
        summary=SECRET_SUMMARY,
        details=SECRET_DETAILS,
        state=State.TRIAGE,
        created_by=owner,
    )
    AdvisoryIntakeMetadata.objects.create(advisory=adv, needs_admin_routing=True)
    return adv


def _assert_no_leak(resp):
    body = resp.content.decode()
    assert resp.status_code == 403, f"expected 403, got {resp.status_code}"
    assert SECRET_SUMMARY not in body, "confidential summary disclosed"
    assert SECRET_DETAILS not in body, "confidential details disclosed"


@pytest.mark.django_db
def test_baseline_outsider_cannot_get_detail(client, draft_advisory, outsider):
    """Control: the regular detail view already forbids the outsider."""
    assert perms.resolved_permission(outsider, draft_advisory) is None
    client.force_login(outsider)
    resp = client.get(reverse("advisories:detail", args=[draft_advisory.advisory_id]))
    assert resp.status_code in (403, 404)
    assert SECRET_SUMMARY.encode() not in resp.content


@pytest.mark.django_db
def test_accept_reassignment_no_leak(client, draft_advisory, outsider):
    """Unknown project_slug used to render the detail page before any auth check
    (any advisory state)."""
    assert perms.resolved_permission(outsider, draft_advisory) is None
    client.force_login(outsider)
    resp = client.post(
        reverse("advisories:accept_reassignment", args=[draft_advisory.advisory_id]),
        {"project_slug": "this.project.does.not.exist"},
    )
    _assert_no_leak(resp)


@pytest.mark.django_db
def test_request_reassignment_no_leak(client, draft_advisory, outsider):
    """Empty note made the service raise ValueError before its auth check; the
    view's non-HTMX recovery path rendered the detail page (any state)."""
    client.force_login(outsider)
    resp = client.post(
        reverse("advisories:request_reassignment", args=[draft_advisory.advisory_id]),
        {"note": ""},
    )
    _assert_no_leak(resp)


@pytest.mark.django_db
def test_reassign_triage_no_leak(client, triage_advisory, outsider):
    """Empty/unknown slug used to render the detail page before any auth check
    (triage-only endpoint)."""
    client.force_login(outsider)
    resp = client.post(
        reverse("advisories:reassign_triage", args=[triage_advisory.advisory_id]),
        {"project_slug": ""},
    )
    _assert_no_leak(resp)


@pytest.mark.django_db
def test_flag_no_leak(client, triage_advisory, outsider):
    """Empty note made the service raise ValueError before its auth check; the
    view's non-HTMX recovery path rendered the detail page (triage-only)."""
    client.force_login(outsider)
    resp = client.post(
        reverse("advisories:flag", args=[triage_advisory.advisory_id]),
        {"note": ""},
    )
    _assert_no_leak(resp)


@pytest.mark.django_db
def test_published_advisory_unpublished_edits_no_leak(client, make_project, make_user, outsider):
    """The realistic precondition: a *published* advisory's ID is public (it is
    the OSV/CSAF filename). An owner edits it post-publication; those edits are
    confidential until republished. An outsider who knows the public ID must not
    read them via the accept-reassignment error path."""
    owner = make_user(email="owner2@example.org")
    project = make_project(name="technology.public", team_members=[owner])
    adv = Advisory.objects.create(
        project=project,
        summary="Original published summary",
        details="Original published details.",
        state=State.PUBLISHED,
        created_by=owner,
    )
    adv.summary = SECRET_SUMMARY
    adv.details = SECRET_DETAILS
    adv.republish_required = True
    adv.save()

    client.force_login(outsider)
    resp = client.post(
        reverse("advisories:accept_reassignment", args=[adv.advisory_id]),
        {"project_slug": "this.project.does.not.exist"},
    )
    _assert_no_leak(resp)
