from __future__ import annotations

import pytest
from django.db import connection, transaction

from audit.models import EPHEMERAL_ACTIONS, AccessLogEntry, Action, AuditLogEntry
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


# ---- record() routing: ledger vs access log -----------------------------


@pytest.mark.django_db
def test_record_routes_ephemeral_action_to_access_log(make_user):
    entry = record(action=Action.ADVISORY_VIEWED, actor=make_user(), metadata={"foo": "bar"})
    assert isinstance(entry, AccessLogEntry)
    assert AccessLogEntry.objects.filter(pk=entry.pk).exists()
    assert not AuditLogEntry.objects.filter(action=Action.ADVISORY_VIEWED).exists()


@pytest.mark.django_db
def test_record_routes_ledger_action_to_audit_log(make_user):
    entry = record(action=Action.ADVISORY_CREATED, actor=make_user())
    assert isinstance(entry, AuditLogEntry)
    assert not AccessLogEntry.objects.filter(action=Action.ADVISORY_CREATED).exists()


@pytest.mark.django_db
def test_every_ephemeral_action_routes_to_access_log(make_user):
    actor = make_user()
    for action in EPHEMERAL_ACTIONS:
        entry = record(action=action, actor=actor)
        assert isinstance(entry, AccessLogEntry), action


@pytest.mark.django_db
def test_access_log_redacts_secrets_in_metadata():
    entry = record(
        action=Action.GHSA_WEBHOOK_RECEIVED,
        metadata={"url": "https://oauth2:ghp_supersecret@github.com/x.git"},
    )
    assert isinstance(entry, AccessLogEntry)
    assert "ghp_supersecret" not in str(entry.metadata)
    assert "***" in str(entry.metadata)


@pytest.mark.django_db
def test_access_log_folds_diff_values_into_metadata():
    entry = record(
        action=Action.ADVISORY_VIEWED,
        previous_value={"a": 1},
        new_value={"b": 2},
        metadata={"k": "v"},
    )
    assert isinstance(entry, AccessLogEntry)
    assert entry.metadata["_previous_value"] == {"a": 1}
    assert entry.metadata["_new_value"] == {"b": 2}
    assert entry.metadata["k"] == "v"


@pytest.mark.django_db
def test_access_log_application_layer_blocks_update():
    entry = record(action=Action.ADVISORY_VIEWED)
    entry.action = Action.GHSA_WEBHOOK_RECEIVED
    with pytest.raises(PermissionError):
        entry.save()


@pytest.mark.django_db
def test_access_log_is_deletable_unlike_ledger():
    """The access log must be droppable for retention — no append-only trigger."""
    entry = record(action=Action.ADVISORY_VIEWED)
    with connection.cursor() as cur:
        cur.execute("DELETE FROM audit_accesslogentry WHERE id = %s", [entry.pk])
    assert not AccessLogEntry.objects.filter(pk=entry.pk).exists()
