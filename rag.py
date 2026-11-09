"""Command-line entry point for Cybersecurity RAG Assistant."""

from cybersecurity_rag.app import run_cli
from cybersecurity_rag.cisa import CISADataError
from cybersecurity_rag.config import ConfigurationError, Settings
from cybersecurity_rag.gemini import GeminiAPIError


def main():
    try:
        return run_cli(Settings.from_env())
    except (ConfigurationError, CISADataError, GeminiAPIError) as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
