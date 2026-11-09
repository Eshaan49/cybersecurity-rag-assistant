"""Application configuration loaded from the process environment."""

from dataclasses import dataclass, field
import os


class ConfigurationError(ValueError):
    """Raised when required application configuration is invalid."""


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str = field(repr=False)
    gemini_model: str = "gemini-3.5-flash-lite"
    cisa_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    request_timeout: float = 30.0
    gemini_timeout: float = 120.0

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        api_key = env.get("GEMINI_API_KEY", "").strip()
        if not api_key:
            raise ConfigurationError(
                "GEMINI_API_KEY is required. Set it in the process environment."
            )
        model = env.get("GEMINI_MODEL", "gemini-3.5-flash-lite").strip()
        if not model:
            raise ConfigurationError("GEMINI_MODEL cannot be empty.")
        return cls(gemini_api_key=api_key, gemini_model=model)
