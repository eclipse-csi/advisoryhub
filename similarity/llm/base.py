"""Shared LLM transport: retry loop, timeouts, lenient JSON extraction.

Secret hygiene (INV-SIM-3): error strings are built from the HTTP status and a
response-body excerpt only — request headers (where the API key travels) are
never interpolated — and :class:`LlmError` additionally runs its message
through ``audit.services.redact_secrets``. ``mark_failed`` redacts a second
time before persisting, mirroring the publication pipeline.
"""

from __future__ import annotations

import json
import logging
import time

import requests

from audit.services import redact_secrets

log = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 10
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF_BASE = 1.5
# 529 is Anthropic's "overloaded"; the rest are standard retryables.
_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504, 529})


class LlmError(Exception):
    """Any transport, HTTP, or response-parsing failure from the provider."""

    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(redact_secrets(str(message)))
        self.status = status


def extract_json(text: str) -> dict:
    """Leniently extract the first JSON object from a model reply.

    Structured-output modes return bare JSON, but local OpenAI-compatible
    servers often can't enforce a schema server-side and wrap the object in
    markdown fences or prose — scan for the first balanced ``{...}`` block.
    """
    stripped = text.strip()
    try:
        loaded = json.loads(stripped)
    except ValueError:
        pass
    else:
        if isinstance(loaded, dict):
            return loaded
    start = stripped.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(stripped)):
            ch = stripped[i]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
            elif ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        loaded = json.loads(stripped[start : i + 1])
                    except ValueError:
                        break
                    if isinstance(loaded, dict):
                        return loaded
                    break
        start = stripped.find("{", start + 1)
    raise LlmError("model reply did not contain a JSON object")


class BaseLlmClient:
    """Common request plumbing; subclasses implement one provider's wire shape."""

    provider = "base"
    default_base_url = ""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "",
        read_timeout: int = 120,
        session: requests.Session | None = None,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or self.default_base_url).rstrip("/")
        self.read_timeout = read_timeout
        self.session = session or requests.Session()

    def complete_json(self, *, system: str, user: str, schema: dict, max_tokens: int) -> dict:
        """One structured completion call returning the parsed JSON object.

        On a JSON-parse failure, retries once with a corrective instruction
        appended to the user message; a second failure raises ``LlmError``.
        """
        text = self._request(system=system, user=user, schema=schema, max_tokens=max_tokens)
        try:
            return extract_json(text)
        except LlmError:
            log.warning(
                "%s: invalid JSON reply; retrying once with corrective prompt", self.provider
            )
            corrective = (
                f"{user}\n\nYour previous reply was not a valid JSON object matching the "
                "schema. Reply with ONLY the JSON object — no prose, no code fences."
            )
            text = self._request(
                system=system, user=corrective, schema=schema, max_tokens=max_tokens
            )
            return extract_json(text)

    def _request(self, *, system: str, user: str, schema: dict, max_tokens: int) -> str:
        """Perform one provider call and return the model's raw text reply."""
        raise NotImplementedError

    def _post(self, url: str, *, headers: dict, body: dict) -> dict:
        """POST with bounded retries on 429/5xx/connection errors."""
        last_error: LlmError | None = None
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                resp = self.session.post(
                    url,
                    headers=headers,
                    json=body,
                    timeout=(_CONNECT_TIMEOUT, self.read_timeout),
                )
            except requests.RequestException as exc:
                last_error = LlmError(f"{self.provider}: request failed: {exc}")
            else:
                if resp.status_code in _RETRYABLE_STATUSES:
                    last_error = LlmError(
                        f"{self.provider}: HTTP {resp.status_code}: {resp.text[:500]}",
                        status=resp.status_code,
                    )
                elif resp.status_code >= 400:
                    raise LlmError(
                        f"{self.provider}: HTTP {resp.status_code}: {resp.text[:500]}",
                        status=resp.status_code,
                    )
                else:
                    try:
                        data = resp.json()
                    except ValueError as exc:
                        raise LlmError(f"{self.provider}: non-JSON response body") from exc
                    if not isinstance(data, dict):
                        raise LlmError(f"{self.provider}: unexpected response shape")
                    return data
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_RETRY_BACKOFF_BASE**attempt)
        assert last_error is not None  # loop always sets it before falling through
        raise last_error
