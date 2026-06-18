"""Durable first-view "acknowledgment of receipt".

Every advisory open lands in the ephemeral ``AccessLogEntry`` as
``ADVISORY_VIEWED`` (90-day retention). A user's *first* open additionally
emits a durable ``ADVISORY_FIRST_SEEN`` ``AuditLogEntry`` that proves they were
made aware and is never auto-pruned. See INV-AUDIT-6 (and INV-AUDIT-3/-5).
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from advisories import timeline as tl
from advisories.models import Advisory
from audit.models import EPHEMERAL_ACTIONS, AccessLogEntry, Action, AuditLogEntry
from audit.retention import forget_user


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    viewer = make_user(email="viewer@example.org")
    other = make_user(email="other@example.org")
    project = make_project("p", team_members=[viewer, other])
    advisory = Advisory.objects.create(project=project, summary="x")
    return {"viewer": viewer, "other": other, "project": project, "advisory": advisory}


def _receipts(advisory, actor=None):
    qs = AuditLogEntry.objects.filter(action=Action.ADVISORY_FIRST_SEEN, advisory=advisory)
    return qs.filter(actor=actor) if actor is not None else qs


# ---- routing: the action stays durable ------------------------------------


def test_first_seen_is_durable_not_ephemeral():
    """The receipt must never join the prunable access log nor the timeline."""
    assert Action.ADVISORY_FIRST_SEEN not in EPHEMERAL_ACTIONS
    assert Action.ADVISORY_FIRST_SEEN not in tl.TIMELINE_ACTIONS_BY_TIER["admin_owner"]
    assert Action.ADVISORY_FIRST_SEEN in tl.EXCLUDED_ACTIONS


# ---- end-to-end through the detail view -----------------------------------


@pytest.mark.django_db
def test_first_open_emits_one_durable_receipt(setup, client):
    client.force_login(setup["viewer"])
    detail = reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    client.get(detail)

    assert _receipts(setup["advisory"], setup["viewer"]).count() == 1
    # The ephemeral every-view row is still written alongside it.
    assert AccessLogEntry.objects.filter(
        action=Action.ADVISORY_VIEWED, advisory=setup["advisory"], actor=setup["viewer"]
    ).exists()


@pytest.mark.django_db
def test_second_open_does_not_duplicate_receipt(setup, client):
    client.force_login(setup["viewer"])
    detail = reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    client.get(detail)
    client.get(detail)

    assert _receipts(setup["advisory"], setup["viewer"]).count() == 1
    # …while every open is still counted ephemerally.
    assert (
        AccessLogEntry.objects.filter(
            action=Action.ADVISORY_VIEWED, advisory=setup["advisory"], actor=setup["viewer"]
        ).count()
        == 2
    )


@pytest.mark.django_db
def test_each_user_gets_their_own_receipt(setup, client):
    detail = reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    client.force_login(setup["viewer"])
    client.get(detail)
    client.force_login(setup["other"])
    client.get(detail)

    assert _receipts(setup["advisory"]).count() == 2
    assert _receipts(setup["advisory"], setup["viewer"]).count() == 1
    assert _receipts(setup["advisory"], setup["other"]).count() == 1


@pytest.mark.django_db
def test_receipt_carries_no_ip_or_user_agent(setup, client):
    """The never-pruned receipt is PII-minimised: no IP/UA (so it is
    erasure-clean — forget_user does not scrub those ledger columns). The
    per-view IP/UA still live on the ephemeral access-log row."""
    client.force_login(setup["viewer"])
    detail = reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    client.get(detail, HTTP_USER_AGENT="pytest-agent", REMOTE_ADDR="203.0.113.7")

    receipt = _receipts(setup["advisory"], setup["viewer"]).get()
    assert receipt.ip_address is None
    assert receipt.user_agent == ""

    # Contrast: the ephemeral view row did capture the request metadata.
    view_row = AccessLogEntry.objects.get(
        action=Action.ADVISORY_VIEWED, advisory=setup["advisory"], actor=setup["viewer"]
    )
    assert view_row.user_agent == "pytest-agent"


@pytest.mark.django_db
def test_forget_user_keeps_receipt_but_deidentifies(setup, client):
    """Erasure leaves the receipt row in place (append-only ledger) but the
    actor degrades to the pseudonymised, deactivated user — proof survives,
    identity does not."""
    client.force_login(setup["viewer"])
    detail = reverse("advisories:detail", args=[setup["advisory"].advisory_id])
    client.get(detail)
    receipt = _receipts(setup["advisory"], setup["viewer"]).get()

    forget_user(setup["viewer"])

    assert AuditLogEntry.objects.filter(pk=receipt.pk).exists()
    setup["viewer"].refresh_from_db()
    assert setup["viewer"].email != "viewer@example.org"
    assert setup["viewer"].is_active is False
