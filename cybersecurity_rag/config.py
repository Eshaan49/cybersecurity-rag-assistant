"""Application configuration loaded from the process environment."""

from dataclasses import dataclass, field
import os


class ConfigurationError(ValueError):
    """Raised when required application configuration is invalid."""


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str = field(default="", repr=False)
    gemini_model: str = "gemini-3.5-flash-lite"
    cisa_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    request_timeout: float = 30.0
    gemini_timeout: float = 120.0
    retrieval_strategy: str = "bm25"
    semantic_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    semantic_index_path: str = ".cache/kev_embeddings.npz"
    nvd_api_key: str = field(default="", repr=False)
    nvd_enabled: bool = False

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        api_key = env.get("GEMINI_API_KEY", "").strip()
        model = env.get("GEMINI_MODEL", "gemini-3.5-flash-lite").strip()
        if not model:
            raise ConfigurationError("GEMINI_MODEL cannot be empty.")
        strategy = env.get("RETRIEVAL_STRATEGY", "bm25").strip().lower()
        if strategy not in {"baseline", "bm25", "semantic", "hybrid"}:
            raise ConfigurationError("RETRIEVAL_STRATEGY must be baseline, bm25, semantic, or hybrid.")
        return cls(gemini_api_key=api_key, gemini_model=model, retrieval_strategy=strategy,
                   semantic_model=env.get("SEMANTIC_MODEL", "sentence-transformers/all-MiniLM-L6-v2").strip(),
                   semantic_index_path=env.get("SEMANTIC_INDEX_PATH", ".cache/kev_embeddings.npz"),
                   nvd_api_key=env.get("NVD_API_KEY", "").strip(),
                   nvd_enabled=env.get("NVD_ENABLED", "false").strip().lower() in {"1", "true", "yes"},
                   cisa_url=env.get("CISA_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").strip())
