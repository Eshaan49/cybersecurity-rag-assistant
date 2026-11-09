from benchmarks.run_benchmark import aggregate_metrics, calculate_metrics, load_benchmark


def test_frozen_catalog_provenance_and_all_labels_resolve():
    metadata, records = load_benchmark()
    assert metadata["catalog"]["version"] == "2026.11.06"
    assert len(records) == 1769
    record_ids = {record["cveID"] for record in records}
    assert all(set(query["relevant_cves"]).issubset(record_ids) for query in metadata["queries"])
    assert len(metadata["queries"]) == 11
    assert sum(query["judgment_status"] == "preliminary_seed" for query in metadata["queries"]) == 7
    assert sum(query["judgment_status"] == "catalog_reviewed_expansion" for query in metadata["queries"]) == 4


def test_metrics_use_p_at_k_recall_at_k_and_reciprocal_rank():
    metadata, records = load_benchmark()
    first_query = next(query for query in metadata["queries"] if query["id"] == "seed_exact_cve")
    target = next(record for record in records if record["cveID"] == "CVE-2026-19868")
    result = calculate_metrics([target], first_query["relevant_cves"], k=3)
    assert result == {"precision_at_k": 1 / 3, "recall_at_k": 1.0,
                      "reciprocal_rank_at_k": 1.0, "hit_at_1": 1.0}


def test_aggregate_metrics_reports_query_count_and_mrr():
    metadata, records = load_benchmark()
    query = next(query for query in metadata["queries"] if query["id"] == "seed_exact_cve")
    exact = next(record for record in records if record["cveID"] == "CVE-2026-19868")
    metrics = aggregate_metrics([query], lambda question, corpus, k: [exact], records, k=3)
    assert metrics["query_count"] == 1
    assert metrics["recall_at_k"] == 1.0
    assert metrics["mrr_at_k"] == 1.0


def test_metric_edges_and_configured_cutoff():
    from benchmarks.run_benchmark import calculate_metrics
    assert calculate_metrics([], ["CVE-2024-12345"], 5) == {
        "precision_at_k": 0.0, "recall_at_k": 0.0,
        "reciprocal_rank_at_k": 0.0, "hit_at_1": 0.0}
    assert calculate_metrics([{"cveID": "CVE-1"}], [], 5)["recall_at_k"] == 0.0
    import pytest
    with pytest.raises(ValueError):
        calculate_metrics([], [], 0)


def test_timing_uses_requested_limit_and_seeded_strategy_order(monkeypatch):
    from benchmarks.run_benchmark import _time_search
    calls = []
    def searcher(q, records, limit):
        calls.append((q, limit))
        return []
    queries = [{"query": "alpha"}]
    first = _time_search({"baseline": searcher, "bm25": searcher}, queries, [], 50, 5, 9)
    assert len(calls) == 102
    assert all(limit == 5 for _, limit in calls)
    calls.clear()
    second = _time_search({"baseline": searcher, "bm25": searcher}, queries, [], 50, 5, 9)
    assert first.keys() == second.keys()
