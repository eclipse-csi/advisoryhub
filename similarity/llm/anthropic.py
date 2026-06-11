"""Anthropic Messages API adapter (raw HTTP, no SDK)."""

from __future__ import annotations

from .base import BaseLlmClient, LlmError

_API_VERSION = "2023-06-01"


class AnthropicClient(BaseLlmClient):
    provider = "anthropic"
    default_base_url = "https://api.anthropic.com"

    def _request(self, *, system: str, user: str, schema: dict, max_tokens: int) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": _API_VERSION,
            "content-type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            # Structured output: the API constrains the reply to valid JSON
            # matching the schema. No sampling params (temperature/top_p/top_k
            # are rejected by current models) and no `thinking` override.
            "output_config": {"format": {"type": "json_schema", "schema": schema}},
        }
        data = self._post(f"{self.base_url}/v1/messages", headers=headers, body=body)
        if data.get("stop_reason") == "refusal":
            raise LlmError("anthropic: model refused the request")
        for block in data.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text":
                return str(block.get("text") or "")
        raise LlmError("anthropic: response contained no text block")
