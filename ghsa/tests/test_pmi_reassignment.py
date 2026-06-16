"""PMI-driven project re-home for GHSA-linked advisories (INV-GHSA-1).

A GHSA-linked advisory's project follows its source repository's PMI
ownership. There is no manual re-assignment path; instead
``sync_project_repos_from_pmi`` re-homes the advisory when PMI maps its
repository to a different project than the one it was originally created under.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.utils import timezone

from advisories.models import Advisory, AdvisoryVersion, Kind, State
from audit.models import Action, AuditLogEntry
from ghsa import services
from projects.models import ProjectGitHubRepository

OWNER, REPO = "eclipse", "widget"
GHSA_ID = "GHSA-aaaa-bbbb-cccc"


def _ghsa_advisory(project, **kwargs):
    return Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id=GHSA_ID,
        ghsa_owner=OWNER,
        ghsa_repo=REPO,
        state=kwargs.pop("state", State.DRAFT),
        **kwargs,
    )


def _active_repo(project):
    ProjectGitHubRepository.objects.create(
        project=project, owner=OWNER, name=REPO, last_seen_in_pmi_at=timezone.now()
    )


def _pmi_map(mapping):
    """Build a ``fetch_project_repos`` side_effect keyed by project slug."""

    def _fetch(slug):
        return list(mapping.get(slug, []))

    return _fetch


@pytest.mark.django_db
def test_pmi_rehomes_advisory_when_repo_moves_projects(make_project):
    old = make_project("proj-old")
    new = make_project("proj-new")
    _active_repo(old)
    advisory = _ghsa_advisory(old)
    before = AdvisoryVersion.objects.filter(advisory=advisory).count()

    with patch("ghsa.services.fetch_project_repos") as mock_pmi:
        mock_pmi.side_effect = _pmi_map({"proj-new": [(OWNER, REPO)]})
        # old no longer lists the repo → its mirror row is soft-removed
        services.sync_project_repos_from_pmi(old, by=None)
        # new now lists the repo → the advisory follows it
        services.sync_project_repos_from_pmi(new, by=None)

    advisory.refresh_from_db()
    assert advisory.project_id == new.pk
    assert advisory.access_review_required_at is not None

    # project_slug is payload-visible, so the move appends a version.
    assert AdvisoryVersion.objects.filter(advisory=advisory).count() == before + 1
    latest = AdvisoryVersion.objects.filter(advisory=advisory).order_by("-version").first()
    assert latest.payload["project_slug"] == "proj-new"

    entry = (
        AuditLogEntry.objects.filter(action=Action.ADVISORY_PROJECT_CHANGED, advisory=advisory)
        .order_by("-created_at")
        .first()
    )
    assert entry is not None
    assert entry.metadata.get("reason") == "pmi_repo_reassignment"
    assert entry.actor_id is None  # system-driven on the beat path


@pytest.mark.django_db
def test_pmi_rehome_published_sets_republish_required(make_project):
    old = make_project("proj-old")
    new = make_project("proj-new")
    _active_repo(old)
    advisory = _ghsa_advisory(old, state=State.PUBLISHED, published_at=timezone.now())

    with patch("ghsa.services.fetch_project_repos") as mock_pmi:
        mock_pmi.side_effect = _pmi_map({"proj-new": [(OWNER, REPO)]})
        services.sync_project_repos_from_pmi(old, by=None)
        services.sync_project_repos_from_pmi(new, by=None)

    advisory.refresh_from_db()
    assert advisory.project_id == new.pk
    assert advisory.republish_required is True


@pytest.mark.django_db
def test_pmi_rehome_is_idempotent(make_project):
    old = make_project("proj-old")
    new = make_project("proj-new")
    _active_repo(old)
    advisory = _ghsa_advisory(old)

    with patch("ghsa.services.fetch_project_repos") as mock_pmi:
        mock_pmi.side_effect = _pmi_map({"proj-new": [(OWNER, REPO)]})
        services.sync_project_repos_from_pmi(old, by=None)
        services.sync_project_repos_from_pmi(new, by=None)
        versions_after_move = AdvisoryVersion.objects.filter(advisory=advisory).count()
        audits_after_move = AuditLogEntry.objects.filter(
            action=Action.ADVISORY_PROJECT_CHANGED, advisory=advisory
        ).count()
        # A second sync of the (now-correct) project must be a no-op.
        services.sync_project_repos_from_pmi(new, by=None)

    assert AdvisoryVersion.objects.filter(advisory=advisory).count() == versions_after_move
    assert (
        AuditLogEntry.objects.filter(
            action=Action.ADVISORY_PROJECT_CHANGED, advisory=advisory
        ).count()
        == audits_after_move
    )


@pytest.mark.django_db
def test_pmi_no_rehome_when_repo_dropped_everywhere(make_project):
    """A repo that disappears from PMI leaves its advisories where they are."""
    old = make_project("proj-old")
    new = make_project("proj-new")
    _active_repo(old)
    advisory = _ghsa_advisory(old)
    before = AdvisoryVersion.objects.filter(advisory=advisory).count()

    with patch("ghsa.services.fetch_project_repos") as mock_pmi:
        mock_pmi.side_effect = _pmi_map({})  # repo gone from every project
        services.sync_project_repos_from_pmi(old, by=None)
        services.sync_project_repos_from_pmi(new, by=None)

    advisory.refresh_from_db()
    assert advisory.project_id == old.pk
    assert AdvisoryVersion.objects.filter(advisory=advisory).count() == before


@pytest.mark.django_db
def test_pmi_defers_rehome_while_old_project_still_claims_repo(make_project):
    """If the current project still actively mirrors the repo, defer (don't
    tug-of-war) — a transient mid-move or PMI double-listing reconciles later."""
    old = make_project("proj-old")
    new = make_project("proj-new")
    _active_repo(old)  # old keeps an *active* row for the repo
    advisory = _ghsa_advisory(old)
    before = AdvisoryVersion.objects.filter(advisory=advisory).count()

    with patch("ghsa.services.fetch_project_repos") as mock_pmi:
        # Only new is synced; old's active claim is untouched this tick.
        mock_pmi.side_effect = _pmi_map({"proj-new": [(OWNER, REPO)]})
        services.sync_project_repos_from_pmi(new, by=None)

    advisory.refresh_from_db()
    assert advisory.project_id == old.pk  # deferred
    assert AdvisoryVersion.objects.filter(advisory=advisory).count() == before


@pytest.mark.django_db(transaction=True)
def test_pmi_rehome_notifies_new_project_team(make_project):
    old = make_project("proj-old")
    new = make_project("proj-new")
    advisory = _ghsa_advisory(old)  # no active old mirror row → re-homes immediately

    with (
        patch("ghsa.services.fetch_project_repos") as mock_pmi,
        patch("advisories.services.queue_advisory_created_notification") as notify,
    ):
        mock_pmi.side_effect = _pmi_map({"proj-new": [(OWNER, REPO)]})
        services.sync_project_repos_from_pmi(new, by=None)

    advisory.refresh_from_db()
    assert advisory.project_id == new.pk
    notify.assert_called_once_with(advisory.pk)
