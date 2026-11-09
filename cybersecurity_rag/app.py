"""Application orchestration, kept separate from the CLI entry point."""

from .cisa import fetch_vulnerabilities
from .gemini import generate_answer
from .retrieval import RetrievalInputError, search


def answer_question(question, vulnerabilities, settings):
    """Retrieve evidence and generate an answer only when evidence exists."""
    results = search(question, vulnerabilities)
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
