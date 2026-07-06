"""Query-count budget guard for the admin inbox.

Companion to ``advisories/tests/test_query_budgets.py`` — the module
docstring there carries the budget-update policy (short version: repeated
SQL shapes in the failure output = an N+1, fix the code; a deliberate new
constant cost = re-measure and bump with a dated comment).

The inbox merges five bounded sources (triage, open reviews, queued CVE
requests, failed/edited publications, orphan CVEs), each with its own
``select_related`` and per-source cap, then paginates in memory — so its
query count is structurally constant. This test pins that property: 10 rows
per source must render in the same number of queries as one.
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from advisories.models import Advisory, AdvisoryIntakeMetadata, State
from advisories.services import record_advisory_version
from workflows.models import CveRequestTask, ReviewTask

HEADROOM = 3

# Measured 2026-07-06.
INBOX_BUDGET = 28 + HEADROOM


@pytest.fixture
def busy_inbox(make_user, make_project, settings):
    """An admin plus 10 open items in each inbox source that tests can seed
    cheaply (triage, open reviews, queued CVE requests)."""
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    submitter = make_user(email="submitter@example.org")
    project = make_project("inbox-project", team_members=[submitter])

    for i in range(10):
        triaged = Advisory.objects.create(
            project=project, state=State.TRIAGE, summary=f"triage {i}"
        )
        AdvisoryIntakeMetadata.objects.create(
            advisory=triaged,
            reporter_display_name=f"reporter {i}",
            needs_admin_routing=(i % 2 == 0),
        )

    for i in range(10):
        drafted = Advisory.objects.create(project=project, summary=f"cve-wanted {i}")
        CveRequestTask.objects.create(advisory=drafted, requested_by=submitter)

    for i in range(10):
        reviewed = Advisory.objects.create(project=project, summary=f"in review {i}")
        version = record_advisory_version(reviewed, editor=submitter)
        ReviewTask.objects.create(advisory=reviewed, version=version, submitted_by=submitter)

    return {"admin": admin}


@pytest.mark.django_db
def test_inbox_query_budget(client, busy_inbox, django_assert_max_num_queries):
    client.force_login(busy_inbox["admin"])
    url = reverse("admin_console:index")
    warm = client.get(url)  # fills the maintenance-mode cache
    assert warm.status_code == 200
    with django_assert_max_num_queries(INBOX_BUDGET):
        response = client.get(url)
    assert response.status_code == 200
