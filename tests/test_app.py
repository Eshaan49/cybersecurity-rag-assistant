from cybersecurity_rag.app import answer_question
from cybersecurity_rag import app
from cybersecurity_rag.config import ConfigurationError, Settings
import pytest


def test_empty_retrieval_does_not_call_model():
    settings = Settings("test-key")
    results, answer = answer_question("unknown galaxy term", [], settings)
    assert results == []
    assert "no answer was generated" in answer


def test_run_cli_fetches_then_prints_answer(monkeypatch):
    settings = Settings("test-key")
    record = {"cveID": "CVE-2024-12345"}
    output = []
    fetched = []

    def fetch(settings_arg):
        fetched.append(settings_arg)
        return [record]

    monkeypatch.setattr(app, "answer_question", lambda question, records, settings_arg: ([record], "Answer"))
    result = app.run_cli(settings, input_fn=lambda prompt: "question", print_fn=output.append, fetch_fn=fetch)
    assert result == 0
    assert fetched == [settings]
    assert any("CVE-2024-12345" in line for line in output)
    assert any("Answer" in line for line in output)


def test_run_cli_reports_empty_question(monkeypatch):
    settings = Settings("test-key")
    output = []
    monkeypatch.setattr(app, "answer_question", answer_question)
    result = app.run_cli(settings, input_fn=lambda prompt: "  ", print_fn=output.append,
                         fetch_fn=lambda settings_arg: [])
    assert result == 2
    assert output == ["Question cannot be empty."]


def test_answer_question_uses_baseline_by_default(monkeypatch):
    calls = []
    monkeypatch.setattr(app, "search", lambda question, records: calls.append("baseline") or [])
    monkeypatch.setattr(app, "BM25Retriever", lambda records: (_ for _ in ()).throw(AssertionError("BM25 selected")))
    _, answer = app.answer_question("query", [], Settings("test-key", retrieval_strategy="baseline"))
    assert calls == ["baseline"]
    assert "no answer was generated" in answer


def test_answer_question_can_select_bm25(monkeypatch):
    monkeypatch.setattr(app, "_BM25_CACHE", None)
    calls = []

    class FakeBM25:
        def __init__(self, records):
            calls.append(("build", records))

        def search(self, question):
            calls.append(("search", question))
            return []

    monkeypatch.setattr(app, "BM25Retriever", FakeBM25)
    monkeypatch.setattr(app, "search", lambda *args: (_ for _ in ()).throw(AssertionError("baseline selected")))
    _, answer = app.answer_question("query", [], Settings("test-key", retrieval_strategy="bm25"))
    assert calls == [("build", []), ("search", "query")]
    assert "no answer was generated" in answer


def test_answer_question_rejects_invalid_direct_strategy():
    with pytest.raises(ConfigurationError, match="retrieval strategy"):
        app.answer_question("query", [], Settings("test-key", retrieval_strategy="invalid"))
