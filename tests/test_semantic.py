import builtins
from pathlib import Path

import numpy as np
import pytest

from cybersecurity_rag.semantic import SemanticDependencyError, SemanticRetriever
from cybersecurity_rag import hybrid as hybrid_module
from cybersecurity_rag.hybrid import HybridRetriever


class FakeModel:
    def __init__(self):
        self.calls = 0

    def encode(self, texts, normalize_embeddings=True):
        self.calls += 1
        return np.asarray([[1.0, 0.0] if "alpha" in text else [0.0, 1.0] for text in texts], dtype=np.float32)


def test_semantic_missing_dependency_is_actionable(monkeypatch):
    original_import = builtins.__import__
    def no_sentence_transformers(name, *args, **kwargs):
        if name == "sentence_transformers":
            raise ImportError("not installed")
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", no_sentence_transformers)
    with pytest.raises(SemanticDependencyError, match="pip install sentence-transformers"):
        SemanticRetriever([], index_path=Path(".pytest_cache") / "embeddings.npz")


def test_embedding_cache_reuses_only_matching_corpus_and_model():
    path = Path(".pytest_cache") / "semantic-vectors-test.npz"
    path.unlink(missing_ok=True)
    first = [{"cveID": "CVE-2024-0001", "shortDescription": "alpha"}]
    model = FakeModel()
    SemanticRetriever(first, model_name="model-a", index_path=path, model=model)
    builds = model.calls
    SemanticRetriever(first, model_name="model-a", index_path=path, model=model)
    assert model.calls == builds
    SemanticRetriever([dict(first[0], shortDescription="changed")], model_name="model-a", index_path=path, model=model)
    assert model.calls == builds + 1
    SemanticRetriever(first, model_name="model-b", index_path=path, model=model)
    assert model.calls == builds + 2
    path.unlink(missing_ok=True)


def test_semantic_search_ranks_and_validates_query():
    records = [
        {"cveID": "CVE-2024-0001", "shortDescription": "alpha vulnerability"},
        {"cveID": "CVE-2024-0002", "shortDescription": "beta vulnerability"},
    ]
    path = Path(".pytest_cache") / "semantic-search-test.npz"
    path.unlink(missing_ok=True)
    retriever = SemanticRetriever(records, index_path=path, model=FakeModel())
    assert retriever.search("alpha query", 1)[0]["cveID"] == "CVE-2024-0001"
    with pytest.raises(ValueError):
        retriever.search("alpha", 0)
    path.unlink(missing_ok=True)


def test_hybrid_dependency_failure_is_explicit(monkeypatch):
    def unavailable(*args, **kwargs):
        raise SemanticDependencyError("semantic dependency unavailable")
    monkeypatch.setattr(hybrid_module, "SemanticRetriever", unavailable)
    with pytest.raises(SemanticDependencyError, match="unavailable"):
        HybridRetriever([], bm25=object())


def test_hybrid_keeps_exact_cve_first(monkeypatch):
    class FakeSemantic:
        def __init__(self, *args, **kwargs):
            pass
        def search(self, question, top_n):
            return [records[1], records[0]]
    records = [
        {"cveID": "CVE-2024-0001", "shortDescription": "alpha"},
        {"cveID": "CVE-2024-0002", "shortDescription": "beta"},
    ]
    monkeypatch.setattr(hybrid_module, "SemanticRetriever", FakeSemantic)
    result = HybridRetriever(records).search("CVE-2024-0001", top_n=2)
    assert [record["cveID"] for record in result][0] == "CVE-2024-0001"
