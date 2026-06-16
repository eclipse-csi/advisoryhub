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


def _ghsa_advisory(project, *, state=State.DRAFT, ghsa_state=GhsaState.PUBLISHED):
    adv = Advisory.objects.create(
        project=project,
        kind=Kind.GHSA_LINKED,
        ghsa_id="GHSA-aaaa-bbbb-cccc",
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
