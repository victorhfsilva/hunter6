"""Provider-agnostic chat client for hunter6 (stdlib only).

The agent loop speaks one neutral message format; each adapter translates it
to the provider's wire format:

* ``openai``    -> ``/chat/completions`` with ``tools`` / ``tool_calls``.
* ``anthropic`` -> ``/messages`` with ``tool_use`` / ``tool_result`` blocks.

Neutral messages::

    {"role": "system", "content": "..."}
    {"role": "user", "content": "..."}
    {"role": "assistant", "content": "...", "tool_calls": [{"id", "name", "arguments"}]}
    {"role": "tool", "tool_call_id": "...", "name": "...", "content": "..."}
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .providers import Provider


class ProviderError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class ChatResult:
    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    finish_reason: str | None = None
    model: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _post(url: str, payload: dict, headers: dict, timeout: int) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    last: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace") if e.fp else ""
            # Retry only transient server errors / rate limits.
            if e.code in (429, 500, 502, 503, 504) and attempt < 2:
                last = ProviderError(f"HTTP {e.code}", status=e.code, body=detail)
                time.sleep(1.5 * (attempt + 1))
                continue
            raise ProviderError(f"provider returned HTTP {e.code}", status=e.code, body=detail)
        except urllib.error.URLError as e:
            last = ProviderError(f"could not reach provider: {e.reason}")
            if attempt < 2:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise last
        except ValueError as e:
            raise ProviderError("provider returned non-JSON body", body=str(e))
    raise last or ProviderError("provider request failed")


# ---------------------------------------------------------------------------
# [OI]-compatible adapter
# ---------------------------------------------------------------------------

def _openai_payload(
    model: str,
    messages: list[dict],
    tools: list[dict] | None,
    temperature: float,
    max_tokens: int | None,
) -> dict:
    wire_messages: list[dict] = []
    for m in messages:
        role = m.get("role")
        if role == "assistant" and m.get("tool_calls"):
            wire_messages.append(
                {
                    "role": "assistant",
                    "content": m.get("content") or "",
                    "tool_calls": [
                        {
                            "id": tc["id"],
                            "type": "function",
                            "function": {
                                "name": tc["name"],
                                "arguments": json.dumps(tc.get("arguments") or {}),
                            },
                        }
                        for tc in m["tool_calls"]
                    ],
                }
            )
        elif role == "tool":
            wire_messages.append(
                {
                    "role": "tool",
                    "tool_call_id": m.get("tool_call_id", ""),
                    "content": m.get("content", ""),
                }
            )
        else:
            wire_messages.append({"role": role, "content": m.get("content", "")})

    payload: dict[str, Any] = {
        "model": model,
        "messages": wire_messages,
        "temperature": temperature,
    }
    if max_tokens:
        payload["max_tokens"] = max_tokens
    if tools:
        payload["tools"] = [
            {"type": "function", "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            }}
            for t in tools
        ]
        payload["tool_choice"] = "auto"
    return payload


def _openai_parse(data: dict) -> ChatResult:
    choices = data.get("choices") or []
    if not choices:
        raise ProviderError("provider returned no choices", body=json.dumps(data)[:2000])
    msg = (choices[0].get("message") or {})
    calls: list[dict] = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        raw_args = fn.get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except ValueError:
            args = {"_raw": raw_args}
        calls.append(
            {
                "id": tc.get("id") or f"call_{len(calls)}",
                "name": fn.get("name", ""),
                "arguments": args if isinstance(args, dict) else {"value": args},
            }
        )
    return ChatResult(
        content=msg.get("content") or "",
        tool_calls=calls,
        finish_reason=choices[0].get("finish_reason"),
        model=data.get("model"),
        usage=data.get("usage") or {},
        raw=data,
    )


# ---------------------------------------------------------------------------
# Anthropic adapter
# ---------------------------------------------------------------------------

def _anthropic_payload(
    model: str,
    messages: list[dict],
    tools: list[dict] | None,
    temperature: float,
    max_tokens: int | None,
) -> dict:
    system_parts = [m["content"] for m in messages if m.get("role") == "system"]
    system = "\n\n".join(p for p in system_parts if p)

    wire: list[dict] = []
    pending_tool_results: list[dict] = []

    def flush_tool_results() -> None:
        if pending_tool_results:
            wire.append({"role": "user", "content": list(pending_tool_results)})
            pending_tool_results.clear()

    for m in messages:
        role = m.get("role")
        if role == "system":
            continue
        if role == "tool":
            pending_tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": m.get("tool_call_id", ""),
                    "content": m.get("content", ""),
                }
            )
            continue
        flush_tool_results()
        if role == "assistant":
            blocks: list[dict] = []
            if m.get("content"):
                blocks.append({"type": "text", "text": m["content"]})
            for tc in m.get("tool_calls") or []:
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["name"],
                        "input": tc.get("arguments") or {},
                    }
                )
            wire.append({"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]})
        else:  # user
            wire.append({"role": "user", "content": m.get("content", "")})
    flush_tool_results()

    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens or 4096,
        "temperature": temperature,
        "messages": wire,
    }
    if system:
        payload["system"] = system
    if tools:
        payload["tools"] = [
            {
                "name": t["name"],
                "description": t["description"],
                "input_schema": t["parameters"],
            }
            for t in tools
        ]
    return payload


def _anthropic_parse(data: dict) -> ChatResult:
    text_parts: list[str] = []
    calls: list[dict] = []
    for block in data.get("content") or []:
        btype = block.get("type")
        if btype == "text":
            text_parts.append(block.get("text") or "")
        elif btype == "tool_use":
            calls.append(
                {
                    "id": block.get("id") or f"call_{len(calls)}",
                    "name": block.get("name", ""),
                    "arguments": block.get("input") or {},
                }
            )
    return ChatResult(
        content="".join(text_parts),
        tool_calls=calls,
        finish_reason=data.get("stop_reason"),
        model=data.get("model"),
        usage=data.get("usage") or {},
        raw=data,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def chat(
    provider: Provider,
    model: str,
    messages: list[dict],
    *,
    tools: list[dict] | None = None,
    temperature: float = 0.2,
    max_tokens: int | None = None,
    timeout: int = 120,
    base_url: str | None = None,
) -> ChatResult:
    api_key = provider.key()
    if provider.requires_key and not api_key:
        raise ProviderError(
            f"no API key for '{provider.id}' — set {provider.api_key_env} "
            "or pass --api-key"
        )
    url = provider.chat_url if not base_url else (
        base_url.rstrip("/") + ("/messages" if provider.kind == "anthropic" else "/chat/completions")
    )

    if provider.kind == "anthropic":
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
            "User-Agent": "hunter6/0.1",
        }
        if api_key:
            headers["x-api-key"] = api_key
        payload = _anthropic_payload(model, messages, tools, temperature, max_tokens)
        return _anthropic_parse(_post(url, payload, headers, timeout))

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "hunter6/0.1",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = _openai_payload(model, messages, tools, temperature, max_tokens)
    return _openai_parse(_post(url, payload, headers, timeout))
