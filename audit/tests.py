from __future__ import annotations

import pytest
from django.db import connection, transaction

from audit.models import Action
from audit.services import record, redact_secrets


@pytest.mark.django_db
def test_record_creates_entry(make_user):
    actor = make_user(email="a@example.org")
    entry = record(
        action=Action.ADVISORY_CREATED,
        actor=actor,
        metadata={"foo": "bar"},
    )
    assert entry.pk is not None
    assert entry.actor == actor
    assert entry.action == Action.ADVISORY_CREATED


@pytest.mark.django_db
def test_record_rejects_unknown_action():
    with pytest.raises(ValueError):
        record(action="bogus.action")


@pytest.mark.django_db
def test_application_layer_blocks_update(make_user):
    entry = record(action=Action.ADVISORY_CREATED, actor=make_user())
    entry.action = Action.ADVISORY_PUBLISHED
    with pytest.raises(PermissionError):
        entry.save()


@pytest.mark.django_db
def test_application_layer_blocks_delete(make_user):
    entry = record(action=Action.ADVISORY_CREATED, actor=make_user())
    with pytest.raises(PermissionError):
        entry.delete()


@pytest.mark.django_db(transaction=True)
def test_database_trigger_blocks_raw_update(make_user):
    """Even raw SQL through the Django connection must be rejected."""
    entry = record(action=Action.ADVISORY_CREATED, actor=make_user())

    with pytest.raises(Exception) as exc:
        with transaction.atomic():
            with connection.cursor() as cur:
                cur.execute(
                    "UPDATE audit_auditlogentry SET action = %s WHERE id = %s",
                    [Action.ADVISORY_PUBLISHED, entry.pk],
                )
    assert "append-only" in str(exc.value).lower()


@pytest.mark.django_db(transaction=True)
def test_database_trigger_blocks_raw_delete(make_user):
    entry = record(action=Action.ADVISORY_CREATED, actor=make_user())

    with pytest.raises(Exception) as exc:
        with transaction.atomic():
            with connection.cursor() as cur:
                cur.execute("DELETE FROM audit_auditlogentry WHERE id = %s", [entry.pk])
    assert "append-only" in str(exc.value).lower()


def test_redact_secrets_scrubs_token_in_url():
    redacted = redact_secrets("https://oauth2:ghp_supersecret@github.com/foo.git")
    assert "ghp_supersecret" not in redacted
    assert "***" in redacted


def test_redact_secrets_scrubs_token_query():
    redacted = redact_secrets("https://example.org/api?token=abcdef")
    assert "abcdef" not in redacted


def test_redact_secrets_scrubs_bearer():
    redacted = redact_secrets({"hdr": "Authorization: Bearer xyz123"})
    assert "xyz123" not in redacted["hdr"]


def test_redact_secrets_recurses_into_nested_structures():
    payload = {"creds": ["https://u:p@host"], "k": {"v": "token=topsecret"}}
    redacted = redact_secrets(payload)
    assert "p@" not in redacted["creds"][0]
    assert "topsecret" not in redacted["k"]["v"]
