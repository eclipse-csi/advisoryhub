"""Adapter wire-shape tests. The HTTP layer is mocked via ``responses``."""

from __future__ import annotations

import json

import pytest
import responses

from similarity.llm import LlmError
from similarity.llm.anthropic import AnthropicClient
from similarity.llm.base import extract_json
from similarity.llm.openai_compat import OpenAICompatClient

SCHEMA = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "additionalProperties": False,
}


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch):
    monkeypatch.setattr("similarity.llm.base.time.sleep", lambda seconds: None)


def _anthropic_reply(text: str) -> dict:
    return {"stop_reason": "end_turn", "content": [{"type": "text", "text": text}]}


def _openai_reply(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


# ---- extract_json ----------------------------------------------------------


def test_extract_json_handles_fences_and_prose():
    assert extract_json('{"ok": true}') == {"ok": True}
    assert extract_json('```json\n{"ok": true}\n```') == {"ok": True}
    assert extract_json('Here you go:\n{"outer": {"inner": "}"}}\nDone.') == {
        "outer": {"inner": "}"}
    }


def test_extract_json_raises_without_object():
    with pytest.raises(LlmError):
        extract_json("no json here")


# ---- Anthropic adapter ------------------------------------------------------


@responses.activate
def test_anthropic_request_shape_and_parse():
    responses.add(
        responses.POST,
        "https://api.anthropic.com/v1/messages",
        json=_anthropic_reply('{"ok": true}'),
        status=200,
    )
    client = AnthropicClient(api_key="sk-ant-test123", model="claude-opus-4-8")
    assert client.complete_json(system="s", user="u", schema=SCHEMA, max_tokens=64) == {"ok": True}

    request = responses.calls[0].request
    assert request.headers["x-api-key"] == "sk-ant-test123"
    assert request.headers["anthropic-version"] == "2023-06-01"
    body = json.loads(request.body)
    assert body["model"] == "claude-opus-4-8"
    assert body["system"] == "s"
    assert body["messages"] == [{"role": "user", "content": "u"}]
    assert body["output_config"] == {"format": {"type": "json_schema", "schema": SCHEMA}}
    # Sampling params and thinking overrides are rejected by current models.
    for forbidden in ("temperature", "top_p", "top_k", "thinking"):
        assert forbidden not in body


@responses.activate
def test_anthropic_refusal_raises():
    responses.add(
        responses.POST,
        "https://api.anthropic.com/v1/messages",
        json={"stop_reason": "refusal", "content": []},
        status=200,
    )
    client = AnthropicClient(api_key="k", model="m")
    with pytest.raises(LlmError, match="refused"):
        client.complete_json(system="s", user="u", schema=SCHEMA, max_tokens=64)


@responses.activate
def test_retry_on_429_then_success():
    responses.add(responses.POST, "https://api.anthropic.com/v1/messages", status=429)
    responses.add(
        responses.POST,
        "https://api.anthropic.com/v1/messages",
        json=_anthropic_reply('{"ok": true}'),
        status=200,
    )
    client = AnthropicClient(api_key="k", model="m")
    assert client.complete_json(system="s", user="u", schema=SCHEMA, max_tokens=64) == {"ok": True}
    assert len(responses.calls) == 2


@responses.activate
def test_exhausted_retries_raise_redacted_error():
    for _ in range(3):
        responses.add(
            responses.POST,
            "https://api.anthropic.com/v1/messages",
            json={"error": "overloaded"},
            status=529,
        )
    client = AnthropicClient(api_key="sk-ant-supersecret-XYZ", model="m")
    with pytest.raises(LlmError) as excinfo:
        client.complete_json(system="s", user="u", schema=SCHEMA, max_tokens=64)
    assert "529" in str(excinfo.value)
    assert "supersecret" not in str(excinfo.value)
    assert len(responses.calls) == 3


@responses.activate
def test_invalid_json_gets_one_corrective_retry():
    responses.add(
        responses.POST,
        "https://api.anthropic.com/v1/messages",
        json=_anthropic_reply("sorry, plain prose"),
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.anthropic.com/v1/messages",
        json=_anthropic_reply('{"ok": true}'),
        status=200,
    )
    client = AnthropicClient(api_key="k", model="m")
    assert client.complete_json(system="s", user="u", schema=SCHEMA, max_tokens=64) == {"ok": True}
    assert len(responses.calls) == 2
    second_body = json.loads(responses.calls[1].request.body)
    assert "not a valid JSON object" in second_body["messages"][0]["content"]


@responses.activate
def test_invalid_json_twice_raises():
    for _ in range(2):
        responses.add(
            responses.POST,
            "https://api.anthropic.com/v1/messages",
            json=_anthropic_reply("still prose"),
            status=200,
        )
    client = AnthropicClient(api_key="k", model="m")
    with pytest.raises(LlmError):
        client.complete_json(system="s", user="u", schema=SCHEMA, max_tokens=64)


# ---- OpenAI-compatible adapter ----------------------------------------------


@responses.activate
def test_openai_request_shape_and_base_url_normalization():
    responses.add(
        responses.POST,
        "http://ollama.local:11434/v1/chat/completions",
        json=_openai_reply('{"ok": true}'),
        status=200,
    )
    # SDK-style base URL including /v1 must not double the suffix.
    client = OpenAICompatClient(
        api_key="local-key", model="llama3", base_url="http://ollama.local:11434/v1"
    )
    assert client.complete_json(system="s", user="u", schema=SCHEMA, max_tokens=64) == {"ok": True}

    request = responses.calls[0].request
    assert request.headers["Authorization"] == "Bearer local-key"
    body = json.loads(request.body)
    assert body["messages"][0] == {"role": "system", "content": "s"}
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["schema"] == SCHEMA


@responses.activate
def test_openai_response_format_400_falls_back_and_parses_fenced_json():
    responses.add(
        responses.POST,
        "https://api.openai.com/v1/chat/completions",
        json={"error": {"message": "response_format is not supported by this model"}},
        status=400,
    )
    responses.add(
        responses.POST,
        "https://api.openai.com/v1/chat/completions",
        json=_openai_reply('```json\n{"ok": true}\n```'),
        status=200,
    )
    client = OpenAICompatClient(api_key="k", model="m")
    assert client.complete_json(system="s", user="u", schema=SCHEMA, max_tokens=64) == {"ok": True}
    assert len(responses.calls) == 2
    retry_body = json.loads(responses.calls[1].request.body)
    assert "response_format" not in retry_body


@responses.activate
def test_openai_keyless_local_server_sends_no_auth_header():
    responses.add(
        responses.POST,
        "http://vllm.local:8000/v1/chat/completions",
        json=_openai_reply('{"ok": true}'),
        status=200,
    )
    client = OpenAICompatClient(api_key="", model="m", base_url="http://vllm.local:8000")
    client.complete_json(system="s", user="u", schema=SCHEMA, max_tokens=64)
    assert "Authorization" not in responses.calls[0].request.headers
