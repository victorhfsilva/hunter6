"""AI provider registry for hunter6.

Two wire formats are supported:

* ``openai``    — [OI]-compatible ``/chat/completions`` with function tools.
                  Covers Verboo, [OI], OpenRouter, Groq, Ollama, and any
                  generic [OI]-compatible gateway.
* ``anthropic`` — the Messages API with ``tool_use`` content blocks.

Adding a provider is one entry in :data:`PROVIDERS`. Keys are read from the
environment (or a user config), never stored in the repository.

Resolution order (first wins) for base URL / key / model:
  1. CLI flags (--base-url / --api-key / --model)
  2. provider-specific env vars, then generic HUNTER6_* / AI_* vars
  3. ~/.config/hunter6/config.json
  4. ~/.config/opencode/opencode.json (Verboo convenience)
  5. baked-in defaults
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Provider:
    id: str
    display_name: str
    kind: str  # "openai" | "anthropic"
    base_url: str
    models: tuple[str, ...]
    default_model: str
    api_key_env: str
    base_url_env: str
    model_env: str
    requires_key: bool = True
    api_key: str | None = None
    base_url_fixed: bool = False
    key_fixed: bool = False

    @property
    def chat_url(self) -> str:
        # Use the fully-resolved base so VERBOO_BASE_URL / HUNTER6_BASE_URL
        # take effect even when the provider came straight from the registry.
        base = self.resolved_base_url().rstrip("/")
        if self.kind == "anthropic":
            return base + "/messages"
        return base + "/chat/completions"

    def model(self, override: str | None = None) -> str:
        if override:
            return override
        return (
            os.environ.get(self.model_env)
            or os.environ.get("AI_MODEL")
            or self.default_model
        )

    def key(self, override: str | None = None) -> str | None:
        if override:
            return override
        if self.key_fixed and self.api_key:
            return self.api_key
        for env in (self.api_key_env, "HUNTER6_API_KEY", "AI_API_KEY"):
            val = os.environ.get(env)
            if val:
                return val
        return self.api_key

    def resolved_base_url(self, override: str | None = None) -> str:
        if override:
            return override
        if self.base_url_fixed and self.base_url:
            return self.base_url
        return (
            os.environ.get(self.base_url_env)
            or os.environ.get("HUNTER6_BASE_URL")
            or os.environ.get("AI_BASE_URL")
            or self.base_url
        )

    def with_overrides(
        self, *, base_url: str | None = None, api_key: str | None = None
    ) -> "Provider":
        return Provider(
            id=self.id,
            display_name=self.display_name,
            kind=self.kind,
            base_url=base_url or self.base_url,
            models=self.models,
            default_model=self.default_model,
            api_key_env=self.api_key_env,
            base_url_env=self.base_url_env,
            model_env=self.model_env,
            requires_key=self.requires_key,
            api_key=api_key or self.api_key,
            base_url_fixed=bool(base_url) or self.base_url_fixed,
            key_fixed=bool(api_key) or self.key_fixed,
        )


PROVIDERS: dict[str, Provider] = {
    "verboo": Provider(
        id="verboo",
        display_name="Verboo Code",
        kind="openai",
        base_url="https://code.verboo.ai/router/v1",
        models=("deepseek-v4.1-flash", "glm-5.3-flash", "kimi-k3"),
        default_model="deepseek-v4.1-flash",
        api_key_env="VERBOO_API_KEY",
        base_url_env="VERBOO_BASE_URL",
        model_env="VERBOO_MODEL",
    ),
    "openai": Provider(
        id="openai",
        display_name="[OI]",
        kind="openai",
        base_url="https://api.openai.com/v1",
        models=("gpt-4o-mini", "gpt-4o", "gpt-4.1"),
        default_model="gpt-4o-mini",
        api_key_env="OPENAI_API_KEY",
        base_url_env="OPENAI_BASE_URL",
        model_env="OPENAI_MODEL",
    ),
    "openrouter": Provider(
        id="openrouter",
        display_name="OpenRouter",
        kind="openai",
        base_url="https://openrouter.ai/api/v1",
        models=(
            "openai/gpt-4o-mini",
            "anthropic/claude-3.5-sonnet",
            "google/gemini-2.5-pro",
        ),
        default_model="openai/gpt-4o-mini",
        api_key_env="OPENROUTER_API_KEY",
        base_url_env="OPENROUTER_BASE_URL",
        model_env="OPENROUTER_MODEL",
    ),
    "groq": Provider(
        id="groq",
        display_name="Groq",
        kind="openai",
        base_url="https://api.groq.com/openai/v1",
        models=("llama-3.3-70b-versatile", "llama-3.1-8b-instant"),
        default_model="llama-3.3-70b-versatile",
        api_key_env="GROQ_API_KEY",
        base_url_env="GROQ_BASE_URL",
        model_env="GROQ_MODEL",
    ),
    "ollama": Provider(
        id="ollama",
        display_name="Ollama (local)",
        kind="openai",
        base_url="http://localhost:11434/v1",
        models=("llama3.1", "qwen2.5", "deepseek-r1"),
        default_model="llama3.1",
        api_key_env="OLLAMA_API_KEY",
        base_url_env="OLLAMA_BASE_URL",
        model_env="OLLAMA_MODEL",
        requires_key=False,
    ),
    "anthropic": Provider(
        id="anthropic",
        display_name="Anthropic",
        kind="anthropic",
        base_url="https://api.anthropic.com/v1",
        models=("claude-sonnet-4-20250514", "claude-3-5-haiku-20241022"),
        default_model="claude-sonnet-4-20250514",
        api_key_env="ANTHROPIC_API_KEY",
        base_url_env="ANTHROPIC_BASE_URL",
        model_env="ANTHROPIC_MODEL",
    ),
    "custom": Provider(
        id="custom",
        display_name="Custom [OI]-compatible endpoint",
        kind="openai",
        base_url="http://localhost:8000/v1",
        models=(),
        default_model="default",
        api_key_env="CUSTOM_API_KEY",
        base_url_env="CUSTOM_BASE_URL",
        model_env="CUSTOM_MODEL",
        requires_key=False,
    ),
}

DEFAULT_PROVIDER = "verboo"


def by_id(provider_id: str) -> Provider | None:
    return PROVIDERS.get((provider_id or "").strip().lower())


def all_ids() -> list[str]:
    return list(PROVIDERS)


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _config_path() -> Path:
    return Path(
        os.environ.get(
            "HUNTER6_CONFIG",
            str(Path.home() / ".config" / "hunter6" / "config.json"),
        )
    )


def _opencode_path() -> Path:
    return Path(
        os.environ.get(
            "HUNTER6_OPENCODE_CONFIG",
            str(Path.home() / ".config" / "opencode" / "opencode.json"),
        )
    )


def resolve(
    provider_id: str | None = None,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
) -> Provider:
    """Return the effective provider after config/env layering."""
    prov = by_id(provider_id or DEFAULT_PROVIDER)
    if prov is None:
        raise KeyError(provider_id)

    cfg = _load_json(_config_path())
    entry = (cfg.get("providers") or {}).get(prov.id) or {}
    base = entry.get("base_url") or entry.get("baseURL")
    key = entry.get("api_key")
    models = tuple(entry.get("models") or prov.models)
    default_model = entry.get("model") or prov.default_model

    # Verboo convenience: reuse the user's OpenCode provider block.
    oc = _load_json(_opencode_path())
    oc_entry = (oc.get("provider") or {}).get(prov.id) or {}
    oc_opts = oc_entry.get("options") or {}
    base = base or oc_opts.get("baseURL")
    key = key or oc_opts.get("apiKey")
    oc_models = oc_entry.get("models") or {}
    if oc_models:
        models = tuple(oc_models.keys())

    merged = Provider(
        id=prov.id,
        display_name=prov.display_name,
        kind=prov.kind,
        base_url=base or prov.base_url,
        models=models,
        default_model=default_model,
        api_key_env=prov.api_key_env,
        base_url_env=prov.base_url_env,
        model_env=prov.model_env,
        requires_key=prov.requires_key,
        api_key=key,
    )
    if base_url or api_key:
        merged = merged.with_overrides(base_url=base_url, api_key=api_key)
    return merged
