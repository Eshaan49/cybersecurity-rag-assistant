import pytest

from cybersecurity_rag.retrieval import RetrievalInputError, search


RECORDS = [
    {"cveID": "CVE-2024-12345", "vendorProject": "Acme", "product": "Widget",
     "vulnerabilityName": "Widget remote flaw", "shortDescription": "Remote code execution."},
    {"cveID": "CVE-2023-98765", "vendorProject": "Other", "product": "Gadget",
     "vulnerabilityName": "Gadget issue", "shortDescription": "Authentication bypass."},
]


def test_exact_cve_match_is_returned_first():
    assert search("details for cve-2023-98765", RECORDS)[0]["cveID"] == "CVE-2023-98765"


def test_search_ranks_matching_vulnerability():
    assert search("Acme Widget remote code execution", RECORDS)[0]["cveID"] == "CVE-2024-12345"


def test_search_normalizes_duplicates_and_punctuation():
    assert search("WIDGET, widget!", RECORDS)[0]["cveID"] == "CVE-2024-12345"


def test_empty_question_is_rejected():
    with pytest.raises(RetrievalInputError):
        search("  ", RECORDS)


def test_no_match_returns_empty_results():
    assert search("quantum banana", RECORDS) == []
