from cybersecurity_rag.app import answer_question
from cybersecurity_rag import app
from cybersecurity_rag.config import Settings


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
