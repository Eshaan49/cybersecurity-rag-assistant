import pytest

from cybersecurity_rag.config import ConfigurationError, Settings


def test_missing_api_key_is_rejected():
    with pytest.raises(ConfigurationError, match="GEMINI_API_KEY"):
        Settings.from_env({})


def test_model_can_be_configured_from_environment():
    settings = Settings.from_env({"GEMINI_API_KEY": "secret", "GEMINI_MODEL": "custom-model"})
    assert settings.gemini_model == "custom-model"
    assert settings.gemini_api_key == "secret"


def test_settings_representation_never_contains_api_key():
    settings = Settings.from_env({"GEMINI_API_KEY": "super-secret-value"})
    assert "super-secret-value" not in repr(settings)
    assert "gemini_api_key" not in repr(settings)
