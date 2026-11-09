import pytest

from benchmarks.run_benchmark import load_benchmark
from cybersecurity_rag.bm25 import BM25Retriever, search_bm25
from cybersecurity_rag.retrieval import RetrievalInputError


@pytest.fixture(scope="module")
def benchmark_data():
    return load_benchmark()


def test_exact_cve_lookup_is_case_insensitive(benchmark_data):
    _, records = benchmark_data
    results = BM25Retriever(records).search("cve-2026-19868")
    assert results[0]["cveID"] == "CVE-2026-19868"


@pytest.mark.parametrize("query,expected", [
    ("SonicWall single-factor authentication SAML MFA bypass", "CVE-2026-19868"),
    ("GitLab Community Edition Enterprise Edition integer overflow regex", "CVE-2026-97229"),
    ("Apache Log4j2 attacker-controlled JNDI endpoints remote code execution", "CVE-2021-44228"),
])
def test_bm25_ranks_catalog_supported_natural_queries_first(benchmark_data, query, expected):
    _, records = benchmark_data
    assert BM25Retriever(records).search(query)[0]["cveID"] == expected


def test_duplicate_cve_records_keep_first_occurrence(benchmark_data):
    _, records = benchmark_data
    first = next(record for record in records if record["cveID"] == "CVE-2026-19868")
    duplicate = dict(first, cveID=" cve-2026-19868 ", vulnerabilityName="duplicate")
    retriever = BM25Retriever([first, duplicate])
    assert len(retriever.records) == 1
    assert retriever.records[0] is first


def test_rank_order_is_deterministic(benchmark_data):
    _, records = benchmark_data
    retriever = BM25Retriever(records)
    query = "Microsoft Exchange Server ProxyLogon remote code execution"
    first = [record["cveID"] for record in retriever.search(query, top_n=10)]
    second = [record["cveID"] for record in retriever.search(query, top_n=10)]
    assert first == second


def test_empty_query_and_no_result_behavior(benchmark_data):
    _, records = benchmark_data
    retriever = BM25Retriever(records)
    with pytest.raises(RetrievalInputError):
        retriever.search("  ")
    assert retriever.search("CVE-1900-0000") == []
    assert retriever.search("zzzznonexistentterm") == []


@pytest.mark.parametrize("top_n", [0, -1])
def test_top_n_must_be_positive(benchmark_data, top_n):
    _, records = benchmark_data
    with pytest.raises(ValueError, match="top_n"):
        BM25Retriever(records).search("Log4j", top_n=top_n)


def test_signature_compatible_wrapper(benchmark_data):
    _, records = benchmark_data
    results = search_bm25("CVE-2021-44228", records, top_n=1)
    assert [record["cveID"] for record in results] == ["CVE-2021-44228"]


def test_manual_bm25_scores_and_tie_breaking():
    records = [
        {"cveID": "CVE-2024-0002", "shortDescription": "alpha alpha beta"},
        {"cveID": "CVE-2024-0001", "shortDescription": "alpha gamma"},
        {"cveID": "CVE-2024-0003", "shortDescription": "delta"},
    ]
    retriever = BM25Retriever(records)
    # alpha: N=3, df=2, IDF=ln(1 + 1.5/2.5); average length is 2.
    idf = __import__("math").log(1 + (3 - 2 + 0.5) / (2 + 0.5))
    dl_first, dl_second, avgdl = 3, 2, 2
    norm_first = 1 - .75 + .75 * dl_first / avgdl
    norm_second = 1 - .75 + .75 * dl_second / avgdl
    expected_first = idf * (2 * 2.5) / (2 + 1.5 * norm_first)
    expected_second = idf * 2.5 / (1 + 1.5 * norm_second)
    assert retriever._document_frequencies["alpha"] == 2
    assert retriever._average_length == avgdl
    assert expected_first > expected_second
    assert [r["cveID"] for r in retriever.search("alpha", 3)] == [
        "CVE-2024-0002", "CVE-2024-0001"]
    # Equal-score documents are ordered by CVE ID, not insertion order.
    tied = BM25Retriever([
        {"cveID": "CVE-2024-0002", "shortDescription": "omega"},
        {"cveID": "CVE-2024-0001", "shortDescription": "omega"},
    ])
    assert [r["cveID"] for r in tied.search("omega", 2)] == ["CVE-2024-0001", "CVE-2024-0002"]


def test_empty_catalog_and_malformed_records_are_safe():
    assert BM25Retriever([]).search("CVE-2024-12345") == []
    assert BM25Retriever([None, "bad", {"cveID": "CVE-2024-12345", "shortDescription": None}]).search("missing") == []


@pytest.mark.parametrize("k1,b", [(0, .75), (-1, .75), (1.5, -0.1), (1.5, 1.1)])
def test_invalid_bm25_parameters(k1, b):
    with pytest.raises(ValueError):
        BM25Retriever([], k1=k1, b=b)
