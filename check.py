"""Manual diagnostic: list Gemini Flash models available to the configured key."""

import requests

from cybersecurity_rag.config import ConfigurationError, Settings


def list_models(settings=None, session=None):
    settings = settings or Settings.from_env()
    client = session or requests
    try:
        response = client.get("https://generativelanguage.googleapis.com/v1beta/models",
                              headers={"x-goog-api-key": settings.gemini_api_key},
                              timeout=settings.request_timeout)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise RuntimeError("Could not retrieve the Gemini model list.") from exc
    except ValueError as exc:
        raise RuntimeError("Gemini returned invalid JSON while listing models.") from exc
    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        raise RuntimeError("Gemini model list response has an unexpected structure.")
    return [model["name"] for model in models if isinstance(model, dict)
            and isinstance(model.get("name"), str) and "flash" in model["name"].lower()]


def main():
    try:
        models = list_models()
    except (ConfigurationError, RuntimeError) as exc:
        print(f"Gemini model check failed: {exc}")
        return 1
    print("Available Flash models:")
    for model in models:
        print(model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
