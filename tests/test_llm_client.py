import os

import pytest

from smt_completeness.llm_client import (
    instructor_mode,
    list_providers,
    openai_client_kwargs,
    resolve_model,
)


def test_list_providers_includes_deepseek():
    providers = list_providers()
    assert "openai" in providers
    assert "deepseek" in providers


def test_resolve_model_defaults():
    assert resolve_model("openai") == "gpt-4o"
    assert resolve_model("deepseek") == "deepseek-chat"
    assert resolve_model("deepseek", "deepseek-reasoner") == "deepseek-reasoner"


def test_resolve_model_unknown_provider():
    with pytest.raises(ValueError, match="未知 LLM provider"):
        resolve_model("unknown-provider")


def test_openai_client_kwargs_deepseek(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-deepseek")
    kwargs = openai_client_kwargs("deepseek")
    assert kwargs["api_key"] == "sk-test-deepseek"
    assert kwargs["base_url"] == "https://api.deepseek.com"


def test_openai_client_kwargs_openai_default_base(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-openai")
    kwargs = openai_client_kwargs("openai")
    assert kwargs["api_key"] == "sk-test-openai"
    assert "base_url" not in kwargs


def test_instructor_mode_deepseek_uses_json():
    import instructor

    assert instructor_mode("deepseek") == instructor.Mode.JSON
    assert instructor_mode("openai") == instructor.Mode.TOOLS


def test_openai_client_kwargs_missing_key(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        openai_client_kwargs("deepseek")
