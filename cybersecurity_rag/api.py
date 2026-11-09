"""FastAPI adapter for the existing cybersecurity RAG package."""
import os
import re
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .bm25 import BM25Retriever
from .cisa import CISADataError, fetch_vulnerabilities
from .config import Settings
from .gemini import GeminiAPIError, generate_answer
from .hybrid import HybridRetriever
from .retrieval import RetrievalInputError, search as baseline_search
from .semantic import SemanticDependencyError

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CISA_CVE_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


class HealthResponse(BaseModel):
    status: Literal["ok"]
    retrieval_strategy: str
    gemini_configured: bool


class Vulnerability(BaseModel):
    cveID: str
    vendorProject: str
    product: str
    vulnerabilityName: str
    dateAdded: str | None = None
    shortDescription: str
    requiredAction: str | None = None
    dueDate: str | None = None
    knownRansomwareCampaignUse: str | None = None
    notes: str | None = None

class VulnerabilityListResponse(BaseModel):
    count: int
    total: int
    retrieval_strategy: str
    items: list[Vulnerability]


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    top_k: int = Field(default=5, ge=1, le=10)


class EvidenceSource(BaseModel):
    cve_id: str
    title: str
    description: str
    vendor: str
    product: str
    url: str


class ChatResponse(BaseModel):
    answer: str
    answer_status: Literal["generated", "insufficient_evidence", "gemini_unconfigured", "generation_error"]
    retrieval_strategy: str
    sources: list[EvidenceSource]
    evidence: list[Vulnerability]


def _source(record):
    cve_id = record["cveID"]
    return EvidenceSource(cve_id=cve_id,
                          title=record["vulnerabilityName"],
                          description=record["shortDescription"],
                          vendor=record["vendorProject"],
                          product=record["product"],
                          url=f"{CISA_CVE_URL}#{cve_id}")


def _retrieve(question, records, settings, top_n):
    if settings.retrieval_strategy == "baseline":
        return baseline_search(question, records, top_n)
    index = BM25Retriever(records)
    if settings.retrieval_strategy == "bm25":
        return index.search(question, top_n)
    return HybridRetriever(records, bm25=index, semantic_model=settings.semantic_model,
                           index_path=settings.semantic_index_path,
                           semantic_only=settings.retrieval_strategy == "semantic").search(question, top_n)


def create_app(settings=None, fetcher=fetch_vulnerabilities):
    settings = settings or Settings.from_env()
    app = FastAPI(title="Cerebro Cybersecurity Intelligence API", version="1.0.0")
    origins = [origin.strip() for origin in os.getenv(
        "FRONTEND_ORIGINS", "http://localhost:3000"
    ).split(",") if origin.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=origins,
                       allow_credentials=False, allow_methods=["GET", "POST"],
                       allow_headers=["Content-Type"])

    def catalog():
        if not hasattr(app.state, "catalog"):
            try:
                app.state.catalog = fetcher(settings)
            except CISADataError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
        return app.state.catalog

    @app.get("/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(status="ok", retrieval_strategy=settings.retrieval_strategy,
                              gemini_configured=bool(settings.gemini_api_key.strip()))

    @app.get("/api/v1/cves", response_model=VulnerabilityListResponse)
    async def list_cves(q: str | None = Query(default=None, max_length=500),
                  vendor: str | None = Query(default=None, max_length=200),
                  limit: int = Query(default=25, ge=1, le=100),
                  offset: int = Query(default=0, ge=0)):
        records = catalog()
        if q and q.strip():
            try:
                selected = _retrieve(q, records, settings, len(records))
            except RetrievalInputError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            except SemanticDependencyError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            # Search is retrieval-only: do not call Gemini for catalogue exploration.
            items = selected
            total = len(items)
        else:
            total = len(records)
            items = records
        if vendor and vendor.strip():
            vendor_key = vendor.strip().casefold()
            items = [item for item in items
                     if str(item.get("vendorProject", "")).strip().casefold() == vendor_key]
            total = len(items)
        return VulnerabilityListResponse(count=len(items[offset:offset + limit]), total=total,
                                         retrieval_strategy=settings.retrieval_strategy,
                                         items=items[offset:offset + limit])

    @app.get("/api/v1/cves/{cve_id}", response_model=Vulnerability)
    async def get_cve(cve_id: str):
        if not CVE_PATTERN.fullmatch(cve_id):
            raise HTTPException(status_code=422, detail="cve_id must use the CVE-YYYY-NNNN format.")
        match = next((item for item in catalog()
                      if item["cveID"].casefold() == cve_id.casefold()), None)
        if match is None:
            raise HTTPException(status_code=404, detail="CVE not found in the CISA KEV catalogue.")
        return match

    @app.post("/api/v1/chat", response_model=ChatResponse)
    async def chat(request: ChatRequest):
        if not request.question.strip():
            raise HTTPException(status_code=422, detail="question cannot be blank.")
        records = catalog()
        try:
            evidence = _retrieve(request.question, records, settings, request.top_k)
        except RetrievalInputError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except SemanticDependencyError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        evidence = evidence[:request.top_k]
        sources = [_source(record) for record in evidence]
        if not evidence:
            return ChatResponse(answer="Insufficient CISA KEV evidence was found to answer this question.",
                                answer_status="insufficient_evidence",
                                retrieval_strategy=settings.retrieval_strategy, sources=[], evidence=[])
        if not settings.gemini_api_key.strip():
            return ChatResponse(answer="Gemini is not configured. Retrieved CISA evidence is provided below; no AI answer was generated.",
                                answer_status="gemini_unconfigured",
                                retrieval_strategy=settings.retrieval_strategy,
                                sources=sources, evidence=evidence)
        try:
            answer = generate_answer(request.question, evidence, settings)
        except GeminiAPIError as exc:
            return ChatResponse(answer=f"The evidence was retrieved, but Gemini could not generate an answer: {exc}",
                                answer_status="generation_error",
                                retrieval_strategy=settings.retrieval_strategy,
                                sources=sources, evidence=evidence)
        return ChatResponse(answer=answer, answer_status="generated",
                            retrieval_strategy=settings.retrieval_strategy,
                            sources=sources, evidence=evidence)

    return app


app = create_app()
