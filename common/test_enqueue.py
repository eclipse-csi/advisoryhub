"""Tests for :func:`common.enqueue.safe_enqueue`.

The contract is: a broker outage (``.delay`` raising) must never escape to
the request that triggered the enqueue, and a healthy broker must receive
the args/kwargs verbatim.
"""

from __future__ import annotations

from common.enqueue import safe_enqueue


class _RaisingTask:
    name = "raising.task"

    def delay(self, *args, **kwargs):
        raise RuntimeError("broker offline")


class _RecordingTask:
    name = "recording.task"

    def __init__(self):
        self.calls = []

    def delay(self, *args, **kwargs):
        self.calls.append((args, kwargs))


def test_safe_enqueue_swallows_broker_errors():
    # Must return normally even though .delay blows up.
    safe_enqueue(_RaisingTask(), 1, event="x")


def test_safe_enqueue_forwards_args_on_success():
    task = _RecordingTask()
    safe_enqueue(task, 1, 2, event="x")
    assert task.calls == [((1, 2), {"event": "x"})]
