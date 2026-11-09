"""Reciprocal Rank Fusion over BM25 and optional semantic retrieval."""
from .bm25 import BM25Retriever
from .semantic import SemanticRetriever
from .retrieval import CVE_RE


class HybridRetriever:
    def __init__(self, records, bm25=None, semantic_model="sentence-transformers/all-MiniLM-L6-v2",
                 index_path=".cache/kev_embeddings.npz", semantic_only=False):
        self.records = list(records)
        self.bm25 = bm25 or BM25Retriever(self.records)
        self.semantic = SemanticRetriever(self.records, semantic_model, index_path)
        self.semantic_only = semantic_only

    def search(self, question, top_n=3):
        exact_ids = list(dict.fromkeys(value.upper() for value in CVE_RE.findall(question)))
        exact_records = [r for wanted in exact_ids for r in self.records
                         if str(r.get("cveID", "")).strip().upper() == wanted]
        if self.semantic_only:
            exact_set = {r.get("cveID") for r in exact_records}
            rest = [r for r in self.semantic.search(question, top_n + len(exact_records))
                    if r.get("cveID") not in exact_set]
            return (exact_records + rest)[:top_n]
        exact = self.bm25.search(question, top_n=top_n)
        semantic = self.semantic.search(question, top_n=top_n)
        # Exact CVE identifiers remain at the front; fuse the remaining ranks.
        ranked = {}
        records = {}
        for results in (exact, semantic):
            for rank, record in enumerate(results, 1):
                cve = record.get("cveID")
                records[cve] = record
                ranked[cve] = ranked.get(cve, 0.0) + 1 / (60 + rank)
        ordered = sorted(ranked, key=lambda cve: (-ranked[cve], str(cve)))
        exact_set = {r.get("cveID") for r in exact_records}
        front = [r.get("cveID") for r in exact_records]
        result_ids = list(dict.fromkeys(front + [c for c in ordered if c not in exact_set]))
        return [records[c] for c in result_ids[:top_n]]
