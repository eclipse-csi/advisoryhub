"""OpenAI Chat Completions adapter — covers OpenAI and local compatible servers.

With the default base URL this talks to OpenAI itself; pointing
``SIMILARITY_LLM_BASE_URL`` at an OpenAI-compatible server (Ollama, vLLM,
LM Studio) keeps advisory content on-prem. Both ``http://host:port`` and the
SDK-style ``http://host:port/v1`` base-URL conventions are accepted.
"""

from __future__ import annotations

from .base import BaseLlmClient, LlmError


class OpenAICompatClient(BaseLlmClient):
    provider = "openai"
    default_base_url = "https://api.openai.com"

    def _request(self, *, system: str, user: str, schema: dict, max_tokens: int) -> str:
        headers = {"content-type": "application/json"}
        # Local servers commonly run keyless; only send auth when configured.
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "result", "schema": schema, "strict": True},
            },
        }
        url = f"{self.base_url.removesuffix('/v1')}/v1/chat/completions"
        try:
            data = self._post(url, headers=headers, body=body)
        except LlmError as exc:
            # Many local servers only support `json_object` or no
            # response_format at all; fall back to prompt-only JSON and let
            # the shared lenient extraction do the parsing.
            if exc.status != 400 or "response_format" not in str(exc):
                raise
            body.pop("response_format", None)
            data = self._post(url, headers=headers, body=body)
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmError("openai: unexpected response shape") from exc
        if not isinstance(content, str) or not content:
            raise LlmError("openai: response contained no message content")
        return content
