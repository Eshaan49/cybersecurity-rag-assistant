import api_test
import check
import search


RECORDS = [{"cveID": "CVE-2024-12345", "vulnerabilityName": "Widget flaw",
            "shortDescription": "A test flaw."}]


def test_search_entry_point_uses_fetch_and_prints_matches(monkeypatch, capsys):
    monkeypatch.setattr(search, "fetch_vulnerabilities", lambda: RECORDS)
    monkeypatch.setattr("builtins.input", lambda prompt: "CVE-2024-12345")
    assert search.main() == 0
    output = capsys.readouterr().out
    assert "CVE-2024-12345" in output
    assert "Widget flaw" in output


def test_api_test_entry_point_reports_catalog(monkeypatch, capsys):
    monkeypatch.setattr(api_test, "fetch_vulnerabilities", lambda: RECORDS)
    assert api_test.main() == 0
    output = capsys.readouterr().out
    assert "Total known exploited vulnerabilities: 1" in output
    assert "CVE-2024-12345" in output


def test_check_entry_point_lists_models_without_printing_key(monkeypatch, capsys):
    monkeypatch.setattr(check, "list_models", lambda: ["models/gemini-flash"])
    assert check.main() == 0
    output = capsys.readouterr().out
    assert "models/gemini-flash" in output
    assert "test-key" not in output
