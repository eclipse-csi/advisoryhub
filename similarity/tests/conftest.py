from __future__ import annotations

import pytest

from similarity.llm import prompts
from similarity.llm.base import BaseLlmClient


class FakeLlmClient(BaseLlmClient):
    """Stub provider: records every call, returns canned fingerprint/judge JSON."""

    provider = "fake"

    def __init__(self):
        super().__init__(api_key="", model="fake-model")
        self.calls: list[dict] = []
        self.judge_matches: list[dict] = []
        self.judge_error: Exception | None = None
        self.fingerprint_error: Exception | None = None
        self.fingerprint_data: dict = {
            "vuln_class": "XSS",
            "component": "web-ui",
            "attack_vector": "crafted URL",
            "affected_versions": "< 2.0",
            "identifiers": [],
            "digest": "Reflected XSS in the web UI search box.",
        }

    def complete_json(self, *, system, user, schema, max_tokens):
        kind = "judge" if system == prompts.JUDGE_SYSTEM else "fingerprint"
        self.calls.append({"kind": kind, "system": system, "user": user, "schema": schema})
        if kind == "judge":
            if self.judge_error is not None:
                raise self.judge_error
            return {"matches": list(self.judge_matches)}
        if self.fingerprint_error is not None:
            raise self.fingerprint_error
        return dict(self.fingerprint_data)

    def call_kinds(self) -> list[str]:
        return [call["kind"] for call in self.calls]


@pytest.fixture
def enable_similarity(settings):
    settings.SIMILARITY_CHECK_ENABLED = True
    settings.SIMILARITY_LLM_PROVIDER = "anthropic"
    settings.SIMILARITY_LLM_MODEL = "fake-model"
    settings.SIMILARITY_LLM_API_KEY = "sk-test-not-a-real-key"
    return settings


@pytest.fixture
def fake_llm(monkeypatch):
    """Replace ``similarity.llm.get_client`` with a recording stub."""
    client = FakeLlmClient()
    monkeypatch.setattr("similarity.llm.get_client", lambda: client)
    return client
