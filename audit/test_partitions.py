"""Tests for AccessLogEntry monthly partition lifecycle (audit.partitions)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import connection
from django.utils import timezone

from audit import partitions
from audit.models import AccessLogEntry, Action
from audit.services import record


def _partition_of(pk: int) -> str:
    with connection.cursor() as cur:
        cur.execute("SELECT tableoid::regclass::text FROM audit_accesslogentry WHERE id = %s", [pk])
        return cur.fetchone()[0]


def _child_partitions() -> set[str]:
    with connection.cursor() as cur:
        cur.execute(
            "SELECT c.relname FROM pg_inherits i "
            "JOIN pg_class c ON c.oid = i.inhrelid "
            "JOIN pg_class p ON p.oid = i.inhparent "
            "WHERE p.relname = 'audit_accesslogentry';"
        )
        return {row[0] for row in cur.fetchall()}


@pytest.mark.django_db
def test_insert_routes_to_current_month_partition():
    entry = record(action=Action.ADVISORY_VIEWED)
    assert isinstance(entry, AccessLogEntry)
    now = timezone.now()
    assert _partition_of(entry.pk).endswith(f"_p{now.year:04d}_{now.month:02d}")


@pytest.mark.django_db
def test_ensure_partition_is_idempotent():
    name1 = partitions.ensure_partition(2031, 5)
    name2 = partitions.ensure_partition(2031, 5)
    assert name1 == name2 == "audit_accesslogentry_p2031_05"
    assert "audit_accesslogentry_p2031_05" in _child_partitions()


@pytest.mark.django_db
def test_ensure_upcoming_creates_current_and_next():
    created = partitions.ensure_upcoming()
    assert len(created) == 2  # current + next month (idempotent if they exist)
    now = timezone.now()
    assert partitions._partition_name(now.year, now.month) in _child_partitions()


@pytest.mark.django_db
def test_drop_old_partitions_drops_only_expired():
    old = timezone.now() - timedelta(days=400)
    partitions.ensure_partition(old.year, old.month)
    # Seed a row physically into the old partition (auto_now_add would stamp
    # "now", so insert via raw SQL with an explicit created_at).
    with connection.cursor() as cur:
        cur.execute(
            "INSERT INTO audit_accesslogentry (action, metadata, user_agent, created_at) "
            "VALUES (%s, '{}', '', %s)",
            [Action.ADVISORY_VIEWED, old],
        )
        # The DEFERRABLE FK constraints queue deferred trigger events on insert;
        # flush them now so DROP TABLE isn't blocked by "pending trigger events"
        # within this single test transaction. (In production the maintenance
        # task drops in its own transaction, well after inserts have committed,
        # so this never arises.)
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE;")
    old_name = partitions._partition_name(old.year, old.month)
    cur_name = partitions._partition_name(timezone.now().year, timezone.now().month)

    assert old_name in partitions.partitions_to_drop(90)
    assert cur_name not in partitions.partitions_to_drop(90)

    dropped = partitions.drop_old_partitions(90)
    assert old_name in dropped
    assert old_name not in _child_partitions()
    assert cur_name in _child_partitions()


@pytest.mark.django_db
def test_partitions_to_drop_rejects_nonpositive():
    with pytest.raises(ValueError):
        partitions.partitions_to_drop(0)


@pytest.mark.django_db
def test_maintain_never_targets_default_partition():
    partitions.maintain(90)
    # The DEFAULT partition is excluded from the drop candidates by construction.
    assert "audit_accesslogentry_default" in _child_partitions()
    assert "audit_accesslogentry_default" not in partitions.partitions_to_drop(1)
