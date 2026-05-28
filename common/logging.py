"""Structured JSON logging + request-id correlation.

A request-scoped ``ContextVar`` holds the X-Request-ID for the duration
of each request (and is propagated into Celery tasks via the helper in
``common.celery_signals``). The :class:`JSONFormatter` renders every
log record as a single-line JSON object, so logs are trivially
shippable to Loki / Cloudwatch / etc. without an extra parser.

Add ``X-Request-ID`` from the load balancer or upstream gateway to keep
the same id end-to-end; otherwise we mint a fresh UUID per request.
"""

from __future__ import annotations

import json
import logging
from contextvars import ContextVar

# Cross-async/threadsafe storage for the current request ID.
_REQUEST_ID: ContextVar[str | None] = ContextVar("request_id", default=None)


def current_request_id() -> str | None:
    return _REQUEST_ID.get()


def set_request_id(rid: str | None) -> object:
    """Set the request id and return the token usable to reset it."""
    return _REQUEST_ID.set(rid)


def reset_request_id(token) -> None:
    _REQUEST_ID.reset(token)


class RequestIDFilter(logging.Filter):
    """Inject ``request_id`` onto every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = current_request_id() or "-"
        return True


class JSONFormatter(logging.Formatter):
    """Single-line JSON log formatter.

    Stable keys: ``ts`` (ISO-8601 UTC), ``level``, ``logger``, ``msg``,
    ``request_id``. Anything passed through ``logger.bind(...)`` /
    ``extra={...}`` is merged into the top-level object as long as the
    key isn't already taken — so ``logger.info("...", extra={"task_id":
    42})`` produces ``{"ts": ..., "task_id": 42, ...}``.
    """

    _RESERVED = {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", None) or "-",
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Merge any custom 'extra' fields the caller passed.
        for k, v in record.__dict__.items():
            if k in self._RESERVED or k in payload or k.startswith("_"):
                continue
            try:
                json.dumps(v)
                payload[k] = v
            except TypeError:
                payload[k] = repr(v)
        return json.dumps(payload, default=str, sort_keys=True)
