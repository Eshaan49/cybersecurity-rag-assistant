"""Manual diagnostic: fetch and summarize the CISA KEV feed."""

from cybersecurity_rag.cisa import CISADataError, fetch_vulnerabilities


def main():
    try:
        vulnerabilities = fetch_vulnerabilities()
    except CISADataError as exc:
        print(f"CISA feed error: {exc}")
        return 1
    print("Total known exploited vulnerabilities:", len(vulnerabilities))
    for item in vulnerabilities[:3]:
        print(item["cveID"], "-", item["vulnerabilityName"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
