"""A dependency-free BM25 retriever kept separate from the baseline search."""

from collections import Counter
import math
import re
import unicodedata

from .retrieval import CVE_RE, RetrievalInputError, STOP


FIELDS = ("vendorProject", "product", "vulnerabilityName", "shortDescription")
TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)


def _canonical_cve(record):
    return str(record.get("cveID", "")).strip().upper()


def _tokenize(text):
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return [token for token in TOKEN_RE.findall(normalized) if token not in STOP and len(token) > 2]


def _query_tokens(question):
    # CVE identifiers have their own exact lookup path; do not score their pieces.
    without_ids = CVE_RE.sub(" ", question)
    return list(dict.fromkeys(_tokenize(without_ids)))


class BM25Retriever:
    """Pre-index a catalog once, then answer queries with Okapi BM25."""

    def __init__(self, vulnerabilities, k1=1.5, b=0.75):
        if k1 <= 0:
            raise ValueError("k1 must be positive.")
        if not 0 <= b <= 1:
            raise ValueError("b must be between 0 and 1.")
        self.k1 = float(k1)
        self.b = float(b)
        self.records = []
        self._record_ids = []
        seen = set()
        for record in vulnerabilities:
            if not isinstance(record, dict):
                continue
            cve_id = _canonical_cve(record)
            if cve_id and cve_id in seen:
                continue
            if cve_id:
                seen.add(cve_id)
            self.records.append(record)
            self._record_ids.append(cve_id)

        self._tokens = []
        self._term_frequencies = []
        self._document_frequencies = Counter()
        total_length = 0
        for record in self.records:
            text = " ".join(str(record.get(field, "")) for field in FIELDS)
            tokens = _tokenize(text)
            frequencies = Counter(tokens)
            self._tokens.append(tokens)
            self._term_frequencies.append(frequencies)
            self._document_frequencies.update(frequencies.keys())
            total_length += len(tokens)
        self._document_count = len(self.records)
        self._average_length = total_length / self._document_count if self._document_count else 0.0
        self._exact_lookup = {cve_id: index for index, cve_id in enumerate(self._record_ids) if cve_id}

    def matches_catalog(self, vulnerabilities):
        """Return whether this index represents the same records in the same order."""
        return len(self.records) == len(vulnerabilities) and all(
            left is right for left, right in zip(self.records, vulnerabilities)
        )

    def search(self, question, top_n=3):
        """Return exact CVE matches first, then deterministically ranked BM25 hits."""
        if not isinstance(question, str) or not question.strip():
            raise RetrievalInputError("Question cannot be empty.")
        if not isinstance(top_n, int) or top_n < 1:
            raise ValueError("top_n must be a positive integer.")

        exact_ids = list(dict.fromkeys(cve.upper() for cve in CVE_RE.findall(question)))
        exact_indices = [self._exact_lookup[cve] for cve in exact_ids if cve in self._exact_lookup]
        exact_set = set(exact_indices)
        terms = _query_tokens(question)
        scores = []
        for index, frequencies in enumerate(self._term_frequencies):
            if index in exact_set:
                continue
            length = len(self._tokens[index])
            score = 0.0
            for term in terms:
                term_frequency = frequencies.get(term, 0)
                document_frequency = self._document_frequencies.get(term, 0)
                if not term_frequency or not document_frequency:
                    continue
                inverse_document_frequency = math.log(
                    1 + (self._document_count - document_frequency + 0.5)
                    / (document_frequency + 0.5)
                )
                normalization = 1 - self.b + self.b * length / self._average_length
                score += inverse_document_frequency * (
                    term_frequency * (self.k1 + 1)
                    / (term_frequency + self.k1 * normalization)
                )
            if score > 0:
                scores.append((score, self._record_ids[index], index))

        scores.sort(key=lambda item: (-item[0], item[1], item[2]))
        ranked_indices = [index for _, _, index in scores]
        ordered_indices = exact_indices + ranked_indices
        return [self.records[index] for index in ordered_indices[:top_n]]


def search_bm25(question, vulnerabilities, top_n=3):
    """Convenience function matching the baseline search signature."""
    return BM25Retriever(vulnerabilities).search(question, top_n=top_n)
