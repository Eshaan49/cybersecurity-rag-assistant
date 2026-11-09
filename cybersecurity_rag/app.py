"""Application orchestration, kept separate from the CLI entry point."""

from .bm25 import BM25Retriever
from .hybrid import HybridRetriever
from .cisa import fetch_vulnerabilities
from .config import ConfigurationError
from .gemini import generate_answer
from .retrieval import RetrievalInputError, search

_BM25_CACHE = None


def answer_question(question, vulnerabilities, settings):
    """Retrieve evidence and generate an answer only when evidence exists."""
    if settings.retrieval_strategy in {"bm25", "hybrid", "semantic"}:
        global _BM25_CACHE
        if (_BM25_CACHE is None or not _BM25_CACHE.matches_catalog(vulnerabilities)
                or any(left != right for left, right in zip(_BM25_CACHE.records, vulnerabilities))):
            _BM25_CACHE = BM25Retriever(vulnerabilities)
        if settings.retrieval_strategy == "bm25":
            results = _BM25_CACHE.search(question)
        else:
            results = HybridRetriever(vulnerabilities, bm25=_BM25_CACHE,
                                     semantic_model=settings.semantic_model,
                                     index_path=settings.semantic_index_path,
                                     semantic_only=settings.retrieval_strategy == "semantic").search(question)
    elif settings.retrieval_strategy == "baseline":
        results = search(question, vulnerabilities)
    else:
        raise ConfigurationError("Unsupported retrieval strategy.")
    if not results:
        return [], "No matching CISA KEV entries were found; no answer was generated."
    return results, generate_answer(question, results, settings)


def run_cli(settings, input_fn=input, print_fn=print, fetch_fn=fetch_vulnerabilities):
    vulnerabilities = fetch_fn(settings)
    question = input_fn("Ask about a vulnerability: ")
    try:
        results, answer = answer_question(question, vulnerabilities, settings)
    except RetrievalInputError as exc:
        print_fn(str(exc))
        return 2
    print_fn("\nSources: " + (", ".join(v["cveID"] for v in results) or "none"))
    print_fn("\nAnswer:\n" + answer)
    return 0
