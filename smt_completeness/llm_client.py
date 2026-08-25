"""LLM provider helpers (OpenAI-compatible clients for instructor)."""

from __future__ import annotations

import os
from typing import Any, Literal

ProviderName = Literal["openai", "deepseek"]

EXTRACT_TEMPERATURE = 0

PROVIDER_CONFIG: dict[str, dict[str, str | None]] = {
    "openai": {
        "base_url": None,
        "api_key_env": "OPENAI_API_KEY",
        "default_model": "gpt-4o",
    },
    "deepseek": {
        # OpenAI-compatible endpoint
        "base_url": "https://api.deepseek.com",
        "api_key_env": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
    },
}


def list_providers() -> list[str]:
    return sorted(PROVIDER_CONFIG.keys())


def resolve_model(provider: str, model: str | None = None) -> str:
    if provider not in PROVIDER_CONFIG:
        raise ValueError(
            f"未知 LLM provider: {provider!r}；可选: {list_providers()}"
        )
    if model:
        return model
    return str(PROVIDER_CONFIG[provider]["default_model"])


def openai_client_kwargs(provider: str) -> dict[str, Any]:
    """Build kwargs for ``openai.OpenAI(**kwargs)``."""
    if provider not in PROVIDER_CONFIG:
        raise ValueError(
            f"未知 LLM provider: {provider!r}；可选: {list_providers()}"
        )
    cfg = PROVIDER_CONFIG[provider]
    env_name = str(cfg["api_key_env"])
    api_key = os.environ.get(env_name)
    if not api_key:
        raise ValueError(
            f"使用 provider={provider!r} 时请设置环境变量 {env_name}"
        )
    kwargs: dict[str, Any] = {"api_key": api_key}
    base_url = cfg["base_url"]
    if base_url:
        kwargs["base_url"] = base_url
    return kwargs


def instructor_mode(provider: str):
    """DeepSeek does not fill OpenAI tool calls; JSON mode is required."""
    import instructor

    if provider == "deepseek":
        return instructor.Mode.JSON
    return instructor.Mode.TOOLS


def build_instructor_client(provider: str = "openai"):
    """Return an instructor-patched OpenAI-compatible client."""
    import instructor
    from openai import OpenAI

    return instructor.from_openai(
        OpenAI(**openai_client_kwargs(provider)),
        mode=instructor_mode(provider),
    )
