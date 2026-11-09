"""Reproducible baseline/BM25 comparison over the frozen CISA KEV catalog."""

import argparse
import hashlib
import json
import random
from pathlib import Path
import statistics
import time

from cybersecurity_rag.bm25 import BM25Retriever
from cybersecurity_rag.cisa import parse_cisa_payload
from cybersecurity_rag.retrieval import search as baseline_search

ROOT = Path(__file__).resolve().parent
QUERY_PATH = ROOT / "queries.json"
DEFAULT_REPEATS = 50
DEFAULT_SEED = 20261106


def load_benchmark():
    metadata = json.loads(QUERY_PATH.read_text(encoding="utf-8"))
    catalog_metadata = metadata["catalog"]
    raw = (ROOT / catalog_metadata["snapshot"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != catalog_metadata["sha256"]:
        raise ValueError("Frozen CISA snapshot SHA-256 does not match benchmark metadata.")
    payload = json.loads(raw.decode("utf-8"))
    if payload.get("catalogVersion") != catalog_metadata["version"]:
        raise ValueError("Frozen CISA snapshot version does not match benchmark metadata.")
    records = parse_cisa_payload(payload)
    if len(records) != catalog_metadata["recordCount"]:
        raise ValueError("Frozen CISA snapshot record count does not match benchmark metadata.")
    ids = {record["cveID"] for record in records}
    for item in metadata["queries"]:
        if not item.get("relevant_cves") or not set(item["relevant_cves"]).issubset(ids):
            raise ValueError(f"Benchmark query {item.get('id')} has an unknown relevance ID.")
    return metadata, records


def calculate_metrics(results, relevant_cves, k=3):
    if not isinstance(k, int) or isinstance(k, bool) or k < 1:
        raise ValueError("k must be a positive integer.")
    relevant = set(relevant_cves)
    ranked = [record["cveID"] for record in results[:k]]
    hits = sum(cve in relevant for cve in ranked)
    rr = next((1 / rank for rank, cve in enumerate(ranked, 1) if cve in relevant), 0.0)
    return {"precision_at_k": hits / k,
            "recall_at_k": hits / len(relevant) if relevant else 0.0,
            "reciprocal_rank_at_k": rr,
            "hit_at_1": float(bool(ranked and ranked[0] in relevant))}


def aggregate_metrics(queries, search_fn, records, k=3):
    rows = [calculate_metrics(search_fn(q["query"], records, k), q["relevant_cves"], k)
            for q in queries]
    if not rows:
        return {"query_count": 0, "precision_at_k": 0.0, "recall_at_k": 0.0,
                "mrr_at_k": 0.0, "hit_at_1": 0.0}
    return {"query_count": len(rows),
            "precision_at_k": statistics.mean(r["precision_at_k"] for r in rows),
            "recall_at_k": statistics.mean(r["recall_at_k"] for r in rows),
            "mrr_at_k": statistics.mean(r["reciprocal_rank_at_k"] for r in rows),
            "hit_at_1": statistics.mean(r["hit_at_1"] for r in rows)}


def _percentiles(samples):
    ordered = sorted(samples)
    if not ordered:
        return {"median_ms": 0.0, "p95_ms": 0.0}
    return {"median_ms": statistics.median(ordered),
            "p95_ms": ordered[max(0, min(len(ordered) - 1, int(0.95 * len(ordered) + 0.999999) - 1))]}


def _time_search(searchers, queries, records, repeats, k, seed):
    rng = random.Random(seed)
    samples = {name: [] for name in searchers}
    # Warm each strategy, then randomize paired order for each query/repetition.
    for query in queries:
        for fn in searchers.values():
            fn(query["query"], records, k)
    for _ in range(repeats):
        for query in queries:
            order = list(searchers.items())
            rng.shuffle(order)
            for name, fn in order:
                started = time.perf_counter_ns()
                fn(query["query"], records, k)
                samples[name].append((time.perf_counter_ns() - started) / 1_000_000)
    return {name: _percentiles(values) for name, values in samples.items()}


def _time_index(records, repeats):
    samples = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        BM25Retriever(records)
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    return _percentiles(samples)


def _time_cold(queries, records, repeats, k, seed):
    rng = random.Random(seed)
    samples = []
    for _ in range(repeats):
        query = queries[rng.randrange(len(queries))]
        start = time.perf_counter_ns()
        BM25Retriever(records).search(query["query"], top_n=k)
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    return _percentiles(samples)


def run_benchmark(repeats=DEFAULT_REPEATS, index_repeats=20, k=3, seed=DEFAULT_SEED):
    if repeats < 50 or index_repeats < 1 or k < 1:
        raise ValueError("repeats must be at least 50; index_repeats and k must be positive.")
    metadata, records = load_benchmark()
    queries = metadata["queries"]
    exact = [q for q in queries if q["type"] == "exact_cve"]
    natural = [q for q in queries if q["type"] == "natural_language"]
    groups = {
        "exact_cve": exact,
        "natural_language_preliminary_seeds": [q for q in natural if q["judgment_status"] == "preliminary_seed"],
        "natural_language_catalog_reviewed_expansions": [q for q in natural if q["judgment_status"] == "catalog_reviewed_expansion"],
        "natural_language_all": natural,
    }
    index = BM25Retriever(records)
    strategies = {
        "baseline": lambda q, corpus, limit: baseline_search(q, corpus, limit),
        "bm25": lambda q, corpus, limit: index.search(q, top_n=limit),
    }
    metrics = {group: {name: aggregate_metrics(items, fn, records, k)
                       for name, fn in strategies.items()} for group, items in groups.items()}
    latency = {group: _time_search(strategies, items, records, repeats, k, seed + n)
               for n, (group, items) in enumerate(groups.items())}
    latency["index_construction"] = {"bm25": _time_index(records, index_repeats)}
    latency["cold_one_query_total"] = {"bm25": _time_cold(queries, records, repeats, k, seed + 100)}
    return {"catalog": metadata["catalog"], "k": k, "repeats_per_query": repeats,
            "index_build_repeats": index_repeats, "sampling_seed": seed,
            "metrics": metrics, "latency": latency,
            "latency_method": "Warm retrieval is measured in paired, seeded-random strategy order; cold BM25 includes one index build and one query. Median and nearest-rank p95 are descriptive for this machine and catalog, not universal claims."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--index-repeats", type=int, default=20)
    parser.add_argument("--k", type=int, default=3)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    print(json.dumps(run_benchmark(args.repeats, args.index_repeats, args.k, args.seed), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
