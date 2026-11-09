"""Optional local Sentence Transformers retrieval with fingerprinted persistence."""
import hashlib
import json
from pathlib import Path

FIELDS = ("vendorProject", "product", "vulnerabilityName", "shortDescription")


class SemanticDependencyError(RuntimeError):
    pass


def _text(record):
    return " ".join(str(record.get(field, "")) for field in FIELDS)


def _fingerprint(records, model_name):
    digest = hashlib.sha256(model_name.encode())
    for record in records:
        digest.update(json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8"))
    return digest.hexdigest()


class SemanticRetriever:
    def __init__(self, records, model_name="sentence-transformers/all-MiniLM-L6-v2",
                 index_path=".cache/kev_embeddings.npz", model=None):
        try:
            import numpy as np
        except ImportError as exc:
            raise SemanticDependencyError("Semantic retrieval requires numpy. Install project dependencies first.") from exc
        if model is None:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:
                raise SemanticDependencyError(
                    "Semantic retrieval is unavailable: install sentence-transformers (pip install sentence-transformers) and make the configured model available locally."
                ) from exc
            model = SentenceTransformer(model_name)
        self.np = np
        self.records = list(records)
        self.model_name = model_name
        self.model = model
        self.index_path = Path(index_path)
        self.fingerprint = _fingerprint(self.records, model_name)
        self.embeddings = self._load_or_build()

    def _load_or_build(self):
        np = self.np
        if self.index_path.exists():
            try:
                with np.load(self.index_path, allow_pickle=False) as data:
                    if str(data["fingerprint"].item()) == self.fingerprint and str(data["model"].item()) == self.model_name:
                        vectors = data["embeddings"]
                    else:
                        vectors = None
                    if vectors is not None and len(vectors) == len(self.records):
                        return vectors
            except (OSError, ValueError, KeyError):
                pass
        vectors = self.model.encode([_text(r) for r in self.records], normalize_embeddings=True)
        vectors = np.asarray(vectors, dtype=np.float32)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.index_path.with_suffix(self.index_path.suffix + ".tmp")
        with tmp.open("wb") as stream:
            np.savez_compressed(stream, embeddings=vectors,
                                fingerprint=np.asarray(self.fingerprint), model=np.asarray(self.model_name))
        tmp.replace(self.index_path)
        return vectors

    def search(self, question, top_n=3):
        if not isinstance(question, str) or not question.strip():
            from .retrieval import RetrievalInputError
            raise RetrievalInputError("Question cannot be empty.")
        if not isinstance(top_n, int) or isinstance(top_n, bool) or top_n < 1:
            raise ValueError("top_n must be a positive integer.")
        query = self.model.encode([question], normalize_embeddings=True)[0]
        scores = self.embeddings @ self.np.asarray(query)
        order = sorted(range(len(scores)), key=lambda i: (-float(scores[i]), str(self.records[i].get("cveID", ""))))
        return [self.records[i] for i in order[:top_n] if float(scores[i]) > 0]
