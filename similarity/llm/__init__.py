"""Provider-independent LLM client for the similarity app.

Thin, hand-rolled adapters over ``requests`` (the project's existing HTTP
client — see ``projects/eclipse_api.py`` and ``ghsa/client.py``); no
provider SDK dependencies. Two providers cover the requirement:

* ``anthropic`` — the Anthropic Messages API.
* ``openai`` — the OpenAI Chat Completions API *and* any local
  OpenAI-compatible server (Ollama, vLLM, LM Studio) via
  ``SIMILARITY_LLM_BASE_URL``, which is the on-prem option for deployments
  that must not send advisory content to a third party.
"""

from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .anthropic import AnthropicClient
from .base import BaseLlmClient, LlmError
from .openai_compat import OpenAICompatClient

__all__ = ["AnthropicClient", "BaseLlmClient", "LlmError", "OpenAICompatClient", "get_client"]


def get_client() -> BaseLlmClient:
    """Build the configured provider client from the ``SIMILARITY_*`` settings."""
    provider = settings.SIMILARITY_LLM_PROVIDER
    kwargs = {
        "api_key": settings.SIMILARITY_LLM_API_KEY,
        "model": settings.SIMILARITY_LLM_MODEL,
        "base_url": settings.SIMILARITY_LLM_BASE_URL,
        "read_timeout": settings.SIMILARITY_LLM_TIMEOUT,
    }
    if provider == "anthropic":
        return AnthropicClient(**kwargs)
    if provider == "openai":
        return OpenAICompatClient(**kwargs)
    raise ImproperlyConfigured(f"Unknown SIMILARITY_LLM_PROVIDER: {provider!r}")
