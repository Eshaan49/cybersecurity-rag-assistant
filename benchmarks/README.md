# Retrieval benchmark

`queries.json` contains seven initial seed queries and four catalog-reviewed natural-language expansion queries. The seven seeds remain explicitly marked `preliminary_seed`; the added multi-CVE labels are marked `catalog_reviewed_expansion`. The latter were checked against the descriptions and product fields in the pinned source catalog, but still benefit from independent security-domain relevance review.

The offline corpus is the official CISA KEV JSON snapshot at catalog version `2026.11.06`, released `2026-11-06T19:44:45.1797Z`, with 1,769 entries. Source: [CISA KEV data repository](https://github.com/cisagov/kev-data), downloaded from `https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json`. SHA-256 is recorded in `queries.json`; the runner verifies it before evaluating. No network access is needed to run tests or the benchmark.

Run from the repository root:

```bash
python -m benchmarks.run_benchmark
```

The runner compares the unchanged rarity-weighted baseline with BM25 on the same corpus and query judgments. It reports Precision@3, Recall@3, and MRR separately for exact-CVE queries, preliminary natural-language seeds, catalog-reviewed expansions, and all natural-language queries. It also reports Hit@1 for the exact-CVE group, so the exact lookup result is clear alongside Precision@3's fixed denominator. Timing reports median and p95 retrieval latency. BM25 index build time and cold one-query end-to-end time are separate from warm query latency. Timing is descriptive and is not asserted in unit tests.

`Precision@3` uses 3 as the denominator even if fewer than 3 results are returned. Relevance judgments are limited to the IDs listed per query; therefore metric quality depends on the completeness of those judgments. The reviewed expansion judgments have been source-checked, not independently approved by a human security reviewer.
