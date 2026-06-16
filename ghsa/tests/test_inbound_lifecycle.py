"""Inbound-only GHSA lifecycle reactions (``react_to_ghsa_state``).

GitHub is the source of truth for a GHSA-linked advisory's lifecycle and
AdvisoryHub mirrors it: auto-publish when GitHub publishes; auto-dismiss when
GitHub closes/withdraws/deletes (the latter covered in the auto-dismiss tests).
AdvisoryHub never writes lifecycle state back to GitHub.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.core.exceptions import PermissionDenied
from django.test import override_settings

from advisories.models import Advisory, GhsaState, Kind, State
from ghsa import services

_OK_SUMMARY = {"changed": ["summary"], "conflict": False, "missing_upstream": False}


def _ghsa_advisory(
    project, *, state=State.DRAFT, ghsa_state=GhsaState.PUBLISHED, ghsa_id="GHSA-aaaa-bbbb-cccc"
):
    adv = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id=ghsa_id,
        ghsa_owner="eclipse",
        ghsa_repo="widget",
        state=state,
        summary="x",
    )
    adv.ghsa_state = ghsa_state
    adv.save(update_fields=["ghsa_state", "modified_at"])
    return adv


# ---- auto-publish on GitHub-published --------------------------------------


@override_settings(GHSA_AUTO_PUBLISH_ENABLED=True)
@pytest.mark.django_db(transaction=True)
def test_react_auto_publishes_published_draft(make_project):
    adv = _ghsa_advisory(make_project("alpha"))
    with patch("ghsa.services.safe_enqueue") as enq:
        services.react_to_ghsa_state(adv, _OK_SUMMARY, by=None)
    assert enq.called


@override_settings(GHSA_AUTO_PUBLISH_ENABLED=True)
@pytest.mark.django_db(transaction=True)
def test_react_no_publish_when_dismissed(make_project):
    """A dismissed advisory is never resurrected by auto-publish."""
    adv = _ghsa_advisory(make_project("alpha"), state=State.DISMISSED)
    with patch("ghsa.services.safe_enqueue") as enq:
        services.react_to_ghsa_state(adv, _OK_SUMMARY, by=None)
    assert not enq.called


@override_settings(GHSA_AUTO_PUBLISH_ENABLED=True)
@pytest.mark.django_db(transaction=True)
def test_react_no_publish_when_ghsa_not_published(make_project):
    adv = _ghsa_advisory(make_project("alpha"), ghsa_state=GhsaState.DRAFT)
    with patch("ghsa.services.safe_enqueue") as enq:
        services.react_to_ghsa_state(adv, _OK_SUMMARY, by=None)
    assert not enq.called


@override_settings(GHSA_AUTO_PUBLISH_ENABLED=True)
@pytest.mark.django_db(transaction=True)
def test_react_no_publish_when_missing_upstream(make_project):
    adv = _ghsa_advisory(make_project("alpha"), ghsa_state=GhsaState.CLOSED)
    summary = {"changed": [], "conflict": False, "missing_upstream": True}
    with patch("ghsa.services.safe_enqueue") as enq:
        services.react_to_ghsa_state(adv, summary, by=None)
    assert not enq.called


@override_settings(GHSA_AUTO_PUBLISH_ENABLED=False)
@pytest.mark.django_db(transaction=True)
def test_react_no_publish_when_flag_off(make_project):
    adv = _ghsa_advisory(make_project("alpha"))
    with patch("ghsa.services.safe_enqueue") as enq:
        services.react_to_ghsa_state(adv, _OK_SUMMARY, by=None)
    assert not enq.called


@pytest.mark.django_db
def test_auto_publish_task_skips_on_gating_failure(make_project):
    """A gating refusal from publish() (CVE conflict / 404 / concurrent run) is
    caught — the auto-publish task never raises and reports it skipped."""
    from ghsa.tasks import run_ghsa_auto_publish

    adv = _ghsa_advisory(make_project("alpha"))
    with patch("publication.services.publish", side_effect=PermissionDenied("nope")):
        result = run_ghsa_auto_publish(adv.advisory_id)
    assert "skipped" in result


# ---- auto-dismiss on GitHub close / withdraw / delete ----------------------


@pytest.mark.django_db
@pytest.mark.parametrize("ghsa_state", [GhsaState.CLOSED, GhsaState.WITHDRAWN])
def test_react_auto_dismisses_closed_or_withdrawn_draft(make_project, ghsa_state):
    adv = _ghsa_advisory(make_project("alpha"), ghsa_state=ghsa_state)
    services.react_to_ghsa_state(
        adv, {"changed": [], "conflict": False, "missing_upstream": False}, by=None
    )
    adv.refresh_from_db()
    assert adv.state == State.DISMISSED
    assert "GitHub" in adv.dismissed_reason


@pytest.mark.django_db
def test_react_auto_dismisses_on_missing_upstream(make_project):
    adv = _ghsa_advisory(make_project("alpha"), ghsa_state=GhsaState.CLOSED)
    services.react_to_ghsa_state(
        adv, {"changed": [], "conflict": False, "missing_upstream": True}, by=None
    )
    adv.refresh_from_db()
    assert adv.state == State.DISMISSED
    assert "deleted" in adv.dismissed_reason


@pytest.mark.django_db
def test_react_does_not_dismiss_published(make_project):
    """A published advisory whose GHSA is withdrawn is not auto-dismissed — it
    can't be (published advisories are undismissable) and the EF feed isn't
    retracted here; it's surfaced for manual handling instead."""
    adv = _ghsa_advisory(
        make_project("alpha"), state=State.PUBLISHED, ghsa_state=GhsaState.WITHDRAWN
    )
    services.react_to_ghsa_state(
        adv, {"changed": [], "conflict": False, "missing_upstream": False}, by=None
    )
    adv.refresh_from_db()
    assert adv.state == State.PUBLISHED


@pytest.mark.django_db
def test_react_does_not_dismiss_when_cve_assigned(make_project):
    """A CVE-bearing advisory is left for an admin — orphaning a CVE is a CNA
    action that can_dismiss keeps admin-only, so the system never does it."""
    adv = _ghsa_advisory(make_project("alpha"), ghsa_state=GhsaState.CLOSED)
    adv.assigned_cve_id = "CVE-2026-0001"
    adv.save(update_fields=["assigned_cve_id", "modified_at"])
    services.react_to_ghsa_state(
        adv, {"changed": [], "conflict": False, "missing_upstream": False}, by=None
    )
    adv.refresh_from_db()
    assert adv.state == State.DRAFT


@override_settings(GHSA_AUTO_PUBLISH_ENABLED=True)
@pytest.mark.django_db(transaction=True)
def test_refresh_for_publish_does_not_auto_publish(make_project, ghsa_payload):
    """refresh_for_publish syncs but must NOT trigger auto-publish — otherwise
    publish() → refresh_for_publish → sync → auto-publish would recurse."""
    adv = _ghsa_advisory(make_project("alpha"))
    with (
        patch("ghsa.services.get_client") as mock_get,
        patch("ghsa.services.safe_enqueue") as enq,
    ):
        mock_get.return_value.get_advisory.return_value = ghsa_payload
        services.refresh_for_publish(adv, by=None)
    assert not enq.called


# ---- auto-withdraw of published advisories (INV-WITHDRAW) ------------------


@pytest.mark.django_db
@pytest.mark.parametrize("ghsa_state", [GhsaState.CLOSED, GhsaState.WITHDRAWN])
def test_react_auto_withdraws_published(make_project, ghsa_state):
    adv = _ghsa_advisory(make_project("alpha"), state=State.PUBLISHED, ghsa_state=ghsa_state)
    with patch("advisories.services.withdraw_advisory") as wd:
        services.react_to_ghsa_state(
            adv, {"changed": [], "conflict": False, "missing_upstream": False}, by=None
        )
    assert wd.called


@pytest.mark.django_db
def test_react_auto_withdraws_published_on_missing_upstream(make_project):
    adv = _ghsa_advisory(make_project("alpha"), state=State.PUBLISHED, ghsa_state=GhsaState.CLOSED)
    with patch("advisories.services.withdraw_advisory") as wd:
        services.react_to_ghsa_state(
            adv, {"changed": [], "conflict": False, "missing_upstream": True}, by=None
        )
    assert wd.called


@pytest.mark.django_db
def test_react_published_with_cve_not_auto_withdrawn(make_project):
    """Orphaning a CVE is admin-only — a CVE-bearing published advisory is left
    flagged for an admin, not auto-withdrawn."""
    adv = _ghsa_advisory(
        make_project("alpha"), state=State.PUBLISHED, ghsa_state=GhsaState.WITHDRAWN
    )
    adv.assigned_cve_id = "CVE-2026-0001"
    adv.save(update_fields=["assigned_cve_id", "modified_at"])
    with patch("advisories.services.withdraw_advisory") as wd:
        services.react_to_ghsa_state(
            adv, {"changed": [], "conflict": False, "missing_upstream": False}, by=None
        )
    assert not wd.called


@pytest.mark.django_db
def test_react_published_still_published_no_withdrawal(make_project):
    adv = _ghsa_advisory(
        make_project("alpha"), state=State.PUBLISHED, ghsa_state=GhsaState.PUBLISHED
    )
    with patch("advisories.services.withdraw_advisory") as wd:
        services.react_to_ghsa_state(
            adv, {"changed": [], "conflict": False, "missing_upstream": False}, by=None
        )
    assert not wd.called


@pytest.mark.django_db
def test_withdraw_ghsa_linked_skips_refresh_for_publish(make_project):
    """A withdrawal skips refresh_for_publish — we're withdrawing precisely
    because the GHSA is gone, so re-validating it would wrongly block."""
    from advisories import services as adv_services

    adv = _ghsa_advisory(make_project("alpha"), state=State.PUBLISHED)
    with patch("ghsa.services.refresh_for_publish") as refresh:
        adv_services.withdraw_advisory(adv, by=None, reason="Linked GHSA was deleted on GitHub.")
    assert not refresh.called
    adv.refresh_from_db()
    assert adv.withdrawn_reason == "Linked GHSA was deleted on GitHub."


# ---- periodic reconcile (poll backstop) ------------------------------------


@override_settings(GHSA_FEATURE_ENABLED=True)
@pytest.mark.django_db
def test_reconcile_syncs_non_terminal_ghsa_linked(make_project):
    """The reconcile sweep re-syncs draft/triage/published GHSA-linked advisories
    (so it can auto-withdraw a published one) — not dismissed ones, and not
    native advisories."""
    project = make_project("alpha")
    draft = _ghsa_advisory(project, state=State.DRAFT, ghsa_id="GHSA-0000-0000-0001")
    triage = _ghsa_advisory(project, state=State.TRIAGE, ghsa_id="GHSA-0000-0000-0002")
    published = _ghsa_advisory(project, state=State.PUBLISHED, ghsa_id="GHSA-0000-0000-0003")
    _ghsa_advisory(project, state=State.DISMISSED, ghsa_id="GHSA-0000-0000-0004")
    Advisory.objects.create(project=project, state=State.DRAFT, summary="native")

    synced: list[int] = []

    def _fake_sync(advisory, *, by):
        synced.append(advisory.pk)
        return {"changed": [], "conflict": False, "missing_upstream": False}

    with (
        patch("ghsa.services.sync_single_ghsa", side_effect=_fake_sync),
        patch("ghsa.services.react_to_ghsa_state"),
    ):
        result = services.reconcile_ghsa_linked_advisories(by=None)

    assert set(synced) == {draft.pk, triage.pk, published.pk}
    assert result["checked"] == 3


@pytest.mark.django_db
def test_reconcile_noop_when_feature_disabled(make_project, settings):
    settings.GHSA_FEATURE_ENABLED = False
    _ghsa_advisory(make_project("alpha"))
    with patch("ghsa.services.sync_single_ghsa") as sync:
        result = services.reconcile_ghsa_linked_advisories(by=None)
    assert "skipped" in result
    assert not sync.called


@override_settings(GHSA_FEATURE_ENABLED=True)
@pytest.mark.django_db
def test_reconcile_continues_past_per_row_error(make_project):
    """A per-advisory GitHub error is logged and skipped — the sweep continues."""
    from ghsa.client import GitHubApiError

    project = make_project("alpha")
    a1 = _ghsa_advisory(project, ghsa_id="GHSA-0000-0000-0001")
    _ghsa_advisory(project, ghsa_id="GHSA-0000-0000-0002")

    def _fake_sync(advisory, *, by):
        if advisory.pk == a1.pk:
            raise GitHubApiError("boom")
        return {"changed": [], "conflict": False, "missing_upstream": False}

    with (
        patch("ghsa.services.sync_single_ghsa", side_effect=_fake_sync),
        patch("ghsa.services.react_to_ghsa_state"),
    ):
        result = services.reconcile_ghsa_linked_advisories(by=None)

    assert result["errors"] == 1
    assert result["checked"] == 1
