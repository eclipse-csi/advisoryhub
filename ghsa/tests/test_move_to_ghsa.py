"""Tests for the "Move to GHSA" action (INV-GHSA-4).

A native triage/draft report is authored as a repository security advisory on
GitHub and converted *in place* to GHSA-linked — the one sanctioned outbound
create and ``kind`` flip. The GitHub HTTP layer is mocked via ``get_client``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from django.core.exceptions import PermissionDenied

from advisories.models import Advisory, AdvisoryVersion, Kind, State
from audit.models import Action, AuditLogEntry
from ghsa import services
from ghsa.client import GitHubApiError
from projects.models import ProjectGitHubRepository

NEW_GHSA_ID = "GHSA-new1-2345-6789"


def _synced_payload(*, state: str = "draft", cve_id: str | None = None) -> dict:
    """A minimal GHSA payload returned by the post-create ``get_advisory``."""
    return {
        "ghsa_id": NEW_GHSA_ID,
        "state": state,
        "cve_id": cve_id,
        "summary": "Moved advisory",
        "description": "Body of the moved advisory.",
        "html_url": f"https://github.com/eclipse/example/security/advisories/{NEW_GHSA_ID}",
    }


def _mock_client(*, pvr: bool = True, created: dict | None = None, synced: dict | None = None):
    client = MagicMock()
    client.get_private_vulnerability_reporting.return_value = pvr
    client.create_repository_advisory.return_value = created or {
        "ghsa_id": NEW_GHSA_ID,
        "state": "draft",
    }
    client.get_advisory.return_value = synced or _synced_payload()
    return client


@pytest.fixture
def owner(make_user):
    return make_user("owner@example.org")


@pytest.fixture
def project_with_pvr_repo(make_project, owner, db):
    project = make_project("eclipse-example", team_members=[owner])
    ProjectGitHubRepository.objects.create(
        project=project,
        owner="eclipse",
        name="example",
        last_seen_in_pmi_at="2026-05-14T12:00:00Z",
        pvr_enabled=True,
        pvr_checked_at="2026-05-14T12:00:00Z",
    )
    return project


def _native(project, *, state=State.TRIAGE, **kwargs):
    return Advisory.objects.create(
        project=project,
        state=state,
        kind=Kind.NATIVE,
        summary=kwargs.pop("summary", "A misfiled report"),
        details=kwargs.pop("details", "It should have been a private report."),
        **kwargs,
    )


@pytest.mark.django_db
def test_move_converts_in_place(project_with_pvr_repo, owner, ghsa_settings):
    advisory = _native(project_with_pvr_repo, state=State.TRIAGE)
    original_pk = advisory.pk
    original_project_id = advisory.project_id

    with patch("ghsa.services.get_client", return_value=_mock_client()):
        result = services.move_advisory_to_ghsa(advisory, owner="eclipse", repo="example", by=owner)

    assert result.pk == original_pk  # converted in place, not a new row
    result.refresh_from_db()
    assert result.kind == Kind.GHSA_LINKED
    assert result.ghsa_id == NEW_GHSA_ID
    assert result.ghsa_owner == "eclipse"
    assert result.ghsa_repo == "example"
    assert result.project_id == original_project_id  # project never changes (INV-GHSA-1)
    # A new immutable version captured the conversion.
    latest = AdvisoryVersion.objects.filter(advisory=result).order_by("-version").first()
    assert latest.payload["kind"] == Kind.GHSA_LINKED
    assert latest.payload["ghsa_id"] == NEW_GHSA_ID
    # Audited.
    assert AuditLogEntry.objects.filter(
        action=Action.ADVISORY_MOVED_TO_GHSA, advisory=result
    ).exists()


@pytest.mark.django_db
def test_move_from_triage_mirrors_draft_state(project_with_pvr_repo, owner, ghsa_settings):
    """A created GHSA is a draft upstream, so a triage source forward-promotes
    to draft via the inbound mirror."""
    advisory = _native(project_with_pvr_repo, state=State.TRIAGE)
    with patch("ghsa.services.get_client", return_value=_mock_client()):
        services.move_advisory_to_ghsa(advisory, owner="eclipse", repo="example", by=owner)
    advisory.refresh_from_db()
    assert advisory.state == State.DRAFT


@pytest.mark.django_db
def test_move_from_draft_stays_draft(project_with_pvr_repo, owner, ghsa_settings):
    advisory = _native(project_with_pvr_repo, state=State.DRAFT)
    with patch("ghsa.services.get_client", return_value=_mock_client()):
        services.move_advisory_to_ghsa(advisory, owner="eclipse", repo="example", by=owner)
    advisory.refresh_from_db()
    assert advisory.state == State.DRAFT
    assert advisory.kind == Kind.GHSA_LINKED


@pytest.mark.django_db
def test_assigned_cve_is_carried_and_does_not_block(project_with_pvr_repo, owner, ghsa_settings):
    advisory = _native(project_with_pvr_repo, state=State.DRAFT, assigned_cve_id="CVE-2026-1234")
    client = _mock_client(synced=_synced_payload(cve_id="CVE-2026-1234"))
    with patch("ghsa.services.get_client", return_value=client):
        services.move_advisory_to_ghsa(advisory, owner="eclipse", repo="example", by=owner)
    advisory.refresh_from_db()
    assert advisory.kind == Kind.GHSA_LINKED
    # The assigned CVE was sent in the create payload.
    _, kwargs = client.create_repository_advisory.call_args
    assert kwargs["payload"]["cve_id"] == "CVE-2026-1234"
    # No spurious conflict (upstream CVE matches ours).
    assert advisory.ghsa_cve_conflict_detected_at is None


@pytest.mark.django_db
def test_non_owner_is_denied(project_with_pvr_repo, make_user, ghsa_settings):
    stranger = make_user("stranger@example.org")
    advisory = _native(project_with_pvr_repo)
    with patch("ghsa.services.get_client", return_value=_mock_client()):
        with pytest.raises(PermissionDenied):
            services.move_advisory_to_ghsa(advisory, owner="eclipse", repo="example", by=stranger)
    advisory.refresh_from_db()
    assert advisory.kind == Kind.NATIVE


@pytest.mark.django_db
def test_published_advisory_cannot_be_moved(project_with_pvr_repo, owner, ghsa_settings):
    advisory = _native(project_with_pvr_repo, state=State.PUBLISHED)
    with patch("ghsa.services.get_client", return_value=_mock_client()):
        with pytest.raises(PermissionDenied):
            services.move_advisory_to_ghsa(advisory, owner="eclipse", repo="example", by=owner)
    advisory.refresh_from_db()
    assert advisory.kind == Kind.NATIVE


@pytest.mark.django_db
def test_repo_not_in_project_is_rejected(project_with_pvr_repo, owner, ghsa_settings):
    advisory = _native(project_with_pvr_repo)
    with patch("ghsa.services.get_client", return_value=_mock_client()):
        with pytest.raises(ValueError, match="not an active repository"):
            services.move_advisory_to_ghsa(
                advisory, owner="eclipse", repo="some-other-repo", by=owner
            )
    advisory.refresh_from_db()
    assert advisory.kind == Kind.NATIVE


@pytest.mark.django_db
def test_pvr_disabled_live_is_rejected(project_with_pvr_repo, owner, ghsa_settings):
    """Cache says enabled (so the button shows) but live GitHub says off."""
    advisory = _native(project_with_pvr_repo)
    with patch("ghsa.services.get_client", return_value=_mock_client(pvr=False)):
        with pytest.raises(ValueError, match="not enabled on the selected repository"):
            services.move_advisory_to_ghsa(advisory, owner="eclipse", repo="example", by=owner)
    advisory.refresh_from_db()
    assert advisory.kind == Kind.NATIVE


@pytest.mark.django_db
def test_github_create_failure_leaves_advisory_native(project_with_pvr_repo, owner, ghsa_settings):
    advisory = _native(project_with_pvr_repo)
    client = _mock_client()
    client.create_repository_advisory.side_effect = GitHubApiError("boom")
    with patch("ghsa.services.get_client", return_value=client):
        with pytest.raises(GitHubApiError):
            services.move_advisory_to_ghsa(advisory, owner="eclipse", repo="example", by=owner)
    advisory.refresh_from_db()
    assert advisory.kind == Kind.NATIVE
    assert advisory.ghsa_id == ""


@pytest.mark.django_db
def test_feature_disabled_is_rejected(project_with_pvr_repo, owner, ghsa_settings):
    ghsa_settings.GHSA_FEATURE_ENABLED = False
    advisory = _native(project_with_pvr_repo)
    with patch("ghsa.services.get_client", return_value=_mock_client()):
        with pytest.raises(ValueError, match="not enabled"):
            services.move_advisory_to_ghsa(advisory, owner="eclipse", repo="example", by=owner)


# ---- payload builder -------------------------------------------------------


@pytest.mark.django_db
def test_payload_builder_maps_fields(project_with_pvr_repo, ghsa_settings):
    advisory = _native(
        project_with_pvr_repo,
        summary="Path traversal",
        details="Detailed body.",
        cwe_ids=["CWE-22"],
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        affected=[
            {
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]}
                ],
            }
        ],
    )
    payload = services.build_repository_advisory_payload(advisory)
    assert payload["summary"] == "Path traversal"
    assert payload["description"] == "Detailed body."
    assert payload["cwe_ids"] == ["CWE-22"]
    assert payload["cvss_vector_string"].startswith("CVSS:3.1/")
    vuln = payload["vulnerabilities"][0]
    assert vuln["package"] == {"ecosystem": "maven", "name": "org.example:lib"}
    assert vuln["vulnerable_version_range"] == ">= 1.0.0, < 1.2.3"
    assert vuln["patched_versions"] == "1.2.3"


@pytest.mark.django_db
def test_payload_builder_falls_back_for_empty_summary(project_with_pvr_repo, ghsa_settings):
    advisory = _native(project_with_pvr_repo, summary="", details="")
    payload = services.build_repository_advisory_payload(advisory)
    assert payload["summary"]  # never empty (GitHub requires it)
    assert payload["description"]  # falls back to summary


# ---- PVR refresh -----------------------------------------------------------


@pytest.mark.django_db
def test_refresh_pvr_status_updates_cache_and_tolerates_errors(make_project, ghsa_settings):
    project = make_project("eclipse-multi")
    good = ProjectGitHubRepository.objects.create(
        project=project, owner="eclipse", name="good", last_seen_in_pmi_at="2026-05-14T12:00:00Z"
    )
    bad = ProjectGitHubRepository.objects.create(
        project=project, owner="eclipse", name="bad", last_seen_in_pmi_at="2026-05-14T12:00:00Z"
    )

    def _pvr(owner, repo):
        if repo == "bad":
            raise GitHubApiError("rate limited")
        return True

    client = MagicMock()
    client.get_private_vulnerability_reporting.side_effect = _pvr
    with patch("ghsa.services.get_client", return_value=client):
        result = services.refresh_pvr_status(project)

    assert result == {"checked": 1, "enabled": 1, "errors": 1}
    good.refresh_from_db()
    bad.refresh_from_db()
    assert good.pvr_enabled is True
    assert good.pvr_checked_at is not None
    assert bad.pvr_enabled is None  # untouched on error


@pytest.mark.django_db
def test_refresh_pvr_status_noop_when_feature_off(make_project, ghsa_settings):
    ghsa_settings.GHSA_FEATURE_ENABLED = False
    project = make_project("eclipse-off")
    assert services.refresh_pvr_status(project) == {"skipped": "GHSA_FEATURE_ENABLED is False"}
