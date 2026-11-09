import pytest

from cybersecurity_rag.config import ConfigurationError, Settings


def test_gemini_key_is_optional_for_retrieval_only_modes():
    assert Settings.from_env({}).gemini_api_key == ""


def test_model_can_be_configured_from_environment():
    settings = Settings.from_env({"GEMINI_API_KEY": "secret", "GEMINI_MODEL": "custom-model"})
    assert settings.gemini_model == "custom-model"
    assert settings.gemini_api_key == "secret"


def test_retrieval_strategy_defaults_to_bm25_and_can_select_other_modes():
    assert Settings.from_env({}).retrieval_strategy == "bm25"
    assert Settings.from_env({"GEMINI_API_KEY": "secret", "RETRIEVAL_STRATEGY": "BM25"}).retrieval_strategy == "bm25"
    assert Settings.from_env({"RETRIEVAL_STRATEGY": "hybrid"}).retrieval_strategy == "hybrid"
    assert Settings.from_env({"RETRIEVAL_STRATEGY": "semantic"}).retrieval_strategy == "semantic"


def test_unknown_retrieval_strategy_is_rejected():
    with pytest.raises(ConfigurationError, match="RETRIEVAL_STRATEGY"):
        Settings.from_env({"GEMINI_API_KEY": "secret", "RETRIEVAL_STRATEGY": "vector"})


def test_settings_representation_never_contains_api_key():
    settings = Settings.from_env({"GEMINI_API_KEY": "super-secret-value"})
    assert "super-secret-value" not in repr(settings)
    assert "gemini_api_key" not in repr(settings)
