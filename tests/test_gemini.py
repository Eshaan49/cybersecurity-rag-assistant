import pytest
import requests
import traceback

from cybersecurity_rag.config import Settings
from cybersecurity_rag.gemini import GeminiAPIError, generate_answer


RECORD = {"cveID": "CVE-2024-12345", "vulnerabilityName": "Widget flaw",
          "shortDescription": "A test flaw."}
SETTINGS = Settings("test-key")


class Response:
    def __init__(self, payload=None, error=False, status_error=None):
        self.payload, self.error, self.status_error = payload, error, status_error

    def raise_for_status(self):
        if self.status_error:
            raise self.status_error

    def json(self):
        if self.error:
            raise ValueError("bad json")
        return self.payload


class Client:
    def __init__(self, response=None, exception=None):
        self.response, self.exception = response, exception
        self.kwargs = None

    def post(self, *args, **kwargs):
        self.kwargs = kwargs
        if self.exception:
            raise self.exception
        return self.response


def test_returns_generated_answer():
    client = Client(Response({"candidates": [{"content": {"parts": [{"text": "Supported answer"}]}}]}))
    assert generate_answer("question", [RECORD], SETTINGS, client) == "Supported answer"
    assert client.kwargs["headers"]["x-goog-api-key"] == "test-key"


def test_api_failure_is_separate_and_does_not_expose_response_body():
    response = requests.Response()
    response.status_code = 403
    error = requests.HTTPError("key=test-key private body", response=response)
    with pytest.raises(GeminiAPIError, match="HTTP status 403") as raised:
        generate_answer("question", [RECORD], SETTINGS, Client(exception=error))
    assert "test-key" not in str(raised.value)
    assert "test-key" not in "".join(traceback.format_exception(raised.value))


def test_timeout_is_sanitized():
    secret = "test-key"
    with pytest.raises(GeminiAPIError, match="timed out") as raised:
        generate_answer("question", [RECORD], SETTINGS, Client(exception=requests.Timeout(secret)))
    assert "test-key" not in str(raised.value)
    assert "test-key" not in "".join(traceback.format_exception(raised.value))


@pytest.mark.parametrize("response", [
    Response(error=True), Response([]), Response({}), Response({"candidates": []}),
    Response({"candidates": [{"finishReason": "SAFETY"}]}),
    Response({"candidates": [{"content": {"parts": []}}]}),
])
def test_malformed_empty_and_blocked_responses_raise(response):
    with pytest.raises(GeminiAPIError):
        generate_answer("question", [RECORD], SETTINGS, Client(response))


@pytest.mark.parametrize("parts", [
    None,
    "not-a-list",
    4,
    [None],
    ["not-a-dict"],
    [{}],
    [{"text": None}],
    [{"text": 42}],
])
def test_malformed_response_parts_raise_gemini_error(parts):
    response = Response({"candidates": [{"content": {"parts": parts}}]})
    with pytest.raises(GeminiAPIError):
        generate_answer("question", [RECORD], SETTINGS, Client(response))


def test_no_evidence_does_not_call_model():
    client = Client()
    with pytest.raises(GeminiAPIError, match="No supporting evidence"):
        generate_answer("question", [], SETTINGS, client)
    assert client.kwargs is None
