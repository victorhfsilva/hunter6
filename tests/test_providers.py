"""Provider registry + client adapter tests (no network)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunter6 import client, providers  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setenv("HUNTER6_CONFIG", "/nonexistent/config.json")
    monkeypatch.setenv("HUNTER6_OPENCODE_CONFIG", "/nonexistent/opencode.json")
    for env in (
        "VERBOO_API_KEY", "VERBOO_BASE_URL", "VERBOO_MODEL",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HUNTER6_API_KEY",
        "AI_API_KEY", "AI_BASE_URL", "AI_MODEL", "HUNTER6_BASE_URL",
    ):
        monkeypatch.delenv(env, raising=False)


def test_registry_has_verboo_default_and_others():
    assert providers.DEFAULT_PROVIDER == "verboo"
    ids = providers.all_ids()
    for expected in ("verboo", "openai", "openrouter", "groq", "ollama", "anthropic", "custom"):
        assert expected in ids


def test_verboo_endpoint_and_models():
    p = providers.by_id("verboo")
    assert p is not None
    assert p.chat_url == "https://code.verboo.ai/router/v1/chat/completions"
    assert p.default_model in p.models
    assert p.kind == "openai"


def test_anthropic_uses_messages_endpoint():
    p = providers.by_id("anthropic")
    assert p is not None
    assert p.kind == "anthropic"
    assert p.chat_url == "https://api.anthropic.com/v1/messages"


def test_resolve_env_and_overrides(monkeypatch):
    monkeypatch.setenv("VERBOO_BASE_URL", "https://env.test/v1")
    monkeypatch.setenv("VERBOO_API_KEY", "env-key")
    monkeypatch.setenv("VERBOO_MODEL", "kimi-k3")
    p = providers.resolve("verboo")
    assert p.resolved_base_url() == "https://env.test/v1"
    assert p.key() == "env-key"
    assert p.model() == "kimi-k3"

    p2 = providers.resolve("verboo", base_url="https://cli.test/v1", api_key="cli-key")
    assert p2.resolved_base_url() == "https://cli.test/v1"
    assert p2.key() == "cli-key"


def test_unknown_provider_raises():
    with pytest.raises(KeyError):
        providers.resolve("nope")


def test_openai_payload_and_parse():
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "name": "probe", "arguments": {"url": "http://x"}}
        ]},
        {"role": "tool", "tool_call_id": "c1", "name": "probe", "content": "ok"},
    ]
    payload = client._openai_payload("m", msgs, [{"name": "probe", "description": "d", "parameters": {"type": "object"}}], 0.2, 100)
    assert payload["model"] == "m"
    assert payload["tools"][0]["function"]["name"] == "probe"
    assert payload["messages"][2]["tool_calls"][0]["function"]["arguments"] == '{"url": "http://x"}'

    data = {
        "model": "m",
        "choices": [{"finish_reason": "tool_calls", "message": {
            "content": "",
            "tool_calls": [{"id": "c9", "function": {"name": "probe", "arguments": '{"url":"y"}'}}],
        }}],
        "usage": {"total_tokens": 3},
    }
    res = client._openai_parse(data)
    assert res.tool_calls[0]["name"] == "probe"
    assert res.tool_calls[0]["arguments"] == {"url": "y"}
    assert res.usage["total_tokens"] == 3


def test_anthropic_payload_and_parse():
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "thinking", "tool_calls": [
            {"id": "t1", "name": "probe", "arguments": {"url": "http://x"}}
        ]},
        {"role": "tool", "tool_call_id": "t1", "name": "probe", "content": "ok"},
    ]
    payload = client._anthropic_payload("m", msgs, [{"name": "probe", "description": "d", "parameters": {"type": "object"}}], 0.2, 512)
    assert payload["system"] == "sys"
    assert payload["messages"][1]["content"][1]["type"] == "tool_use"
    assert payload["messages"][2]["content"][0]["type"] == "tool_result"
    assert payload["tools"][0]["input_schema"] == {"type": "object"}

    data = {"model": "m", "stop_reason": "tool_use", "content": [
        {"type": "text", "text": "hi"},
        {"type": "tool_use", "id": "t1", "name": "probe", "input": {"url": "z"}},
    ]}
    res = client._anthropic_parse(data)
    assert res.content == "hi"
    assert res.tool_calls[0]["arguments"] == {"url": "z"}


def test_missing_key_raises():
    p = providers.resolve("verboo")
    with pytest.raises(client.ProviderError):
        client.chat(p, "m", [{"role": "user", "content": "hi"}])
