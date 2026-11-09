"""Compatibility CLI for searching CISA KEV without calling Gemini."""

from cybersecurity_rag.cisa import CISADataError, fetch_vulnerabilities
from cybersecurity_rag.retrieval import RetrievalInputError, search


def main():
    try:
        vulnerabilities = fetch_vulnerabilities()
        question = input("Ask about a vulnerability: ")
        results = search(question, vulnerabilities)
    except (CISADataError, RetrievalInputError) as exc:
        print(f"Error: {exc}")
        return 1
    if not results:
        print("No matching CISA KEV entries found.")
        return 0
    for item in results:
        print(f'\n{item["cveID"]} - {item["vulnerabilityName"]}')
        print(item["shortDescription"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
