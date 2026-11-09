"""Lexical retrieval for CISA KEV vulnerability records."""

import re

STOP = {"what", "does", "how", "with", "that", "this", "from", "work", "works",
        "about", "which", "when", "where", "into", "have", "been", "explain"}
TOKEN_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class RetrievalInputError(ValueError):
    """Raised when a retrieval query is empty or invalid."""


def _search_text(record):
    fields = ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription")
    return " ".join(str(record.get(field, "")) for field in fields).lower()


def search(question, vulnerabilities, top_n=3):
    """Return exact CVE matches first, then rarity-weighted lexical matches."""
    if not isinstance(question, str) or not question.strip():
        raise RetrievalInputError("Question cannot be empty.")
    if not isinstance(top_n, int) or top_n < 1:
        raise ValueError("top_n must be a positive integer.")
    query = question.strip()
    texts = [(record, _search_text(record)) for record in vulnerabilities]
    cve_ids = {value.upper() for value in CVE_RE.findall(query)}
    exact = [record for record, _ in texts if str(record.get("cveID", "")).upper() in cve_ids]
    if exact:
        seen = {str(record.get("cveID", "")).upper() for record in exact}
        remainder = _rank_terms(query, texts, excluded_ids=seen)
        return (exact + remainder)[:top_n]
    return _rank_terms(query, texts)[:top_n]


def _rank_terms(query, texts, excluded_ids=None):
    excluded_ids = excluded_ids or set()
    words = []
    for token in TOKEN_RE.findall(query.lower()):
        if len(token) > 3 and token not in STOP and token not in words:
            words.append(token)
    weights = {}
    for word in words:
        document_frequency = sum(word in text for _, text in texts)
        weights[word] = 1 / document_frequency if document_frequency else 0
    scored = []
    for record, text in texts:
        cve_id = str(record.get("cveID", "")).upper()
        if cve_id in excluded_ids:
            continue
        score = sum(weights[word] * text.count(word) for word in words)
        if score > 0:
            scored.append((score, record))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [record for _, record in scored]
