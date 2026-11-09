from fastapi import HTTPException
import pytest

from cybersecurity_rag import api
from cybersecurity_rag.config import Settings

RECORDS = [{
    "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
    "vulnerabilityName": "Apache Log4j2 remote code execution vulnerability",
    "dateAdded": "2021-12-10", "shortDescription": "An attacker could execute code.",
    "requiredAction": "Apply updates.", "dueDate": "2021-12-24",
    "knownRansomwareCampaignUse": "Known",
}]


def route(app, path):
    return next(item.endpoint for item in app.routes if getattr(item, "path", None) == path)


def call(endpoint, *args, **kwargs):
    coroutine = endpoint(*args, **kwargs)
    try:
        coroutine.send(None)
    except StopIteration as result:
        return result.value
    raise AssertionError("API handler unexpectedly performed asynchronous I/O")


def test_health_and_cve_endpoints_use_mocked_catalog():
    app = api.create_app(Settings(), fetcher=lambda _: RECORDS)
    assert call(route(app, "/health")).retrieval_strategy == "bm25"
    listing = call(route(app, "/api/v1/cves"), q="CVE-2021-44228", vendor=None, limit=25, offset=0)
    assert listing.items[0].cveID == "CVE-2021-44228"
    assert call(route(app, "/api/v1/cves/{cve_id}"), "CVE-2021-44228")["cveID"] == "CVE-2021-44228"
    with pytest.raises(HTTPException) as not_found:
        call(route(app, "/api/v1/cves/{cve_id}"), "CVE-2021-99999")
    assert not_found.value.status_code == 404
    with pytest.raises(HTTPException) as invalid:
        call(route(app, "/api/v1/cves/{cve_id}"), "not-a-cve")
    assert invalid.value.status_code == 422


def test_vendor_filter_uses_exact_cisa_vendor_metadata():
    records = RECORDS + [{
        "cveID": "CVE-2024-12345", "vendorProject": "Apple", "product": "iOS",
        "vulnerabilityName": "Remote code execution", "shortDescription": "Remote code execution flaw.",
    }, {
        "cveID": "CVE-2024-22222", "vendorProject": "Microsoft", "product": "Windows",
        "vulnerabilityName": "Remote code execution", "shortDescription": "Remote code execution flaw.",
    }]
    app = api.create_app(Settings(), fetcher=lambda _: records)
    listing = call(route(app, "/api/v1/cves"), q="remote code execution",
                   vendor="microsoft", limit=25, offset=0)
    assert listing.total == 1
    assert [item.vendorProject for item in listing.items] == ["Microsoft"]


def test_chat_returns_real_evidence_without_gemini_key():
    app = api.create_app(Settings(), fetcher=lambda _: RECORDS)
    body = call(route(app, "/api/v1/chat"), api.ChatRequest(question="CVE-2021-44228"))
    assert body.answer_status == "gemini_unconfigured"
    assert body.sources[0].cve_id == "CVE-2021-44228"
    assert body.evidence[0].shortDescription == RECORDS[0]["shortDescription"]


def test_chat_generates_from_mocked_gemini_and_abstains_without_evidence(monkeypatch):
    monkeypatch.setattr(api, "generate_answer", lambda question, evidence, settings: "Grounded test answer")
    app = api.create_app(Settings(gemini_api_key="test-key"), fetcher=lambda _: RECORDS)
    generated = call(route(app, "/api/v1/chat"), api.ChatRequest(question="CVE-2021-44228"))
    assert generated.answer_status == "generated"
    assert generated.answer == "Grounded test answer"
    empty = api.create_app(Settings(), fetcher=lambda _: [])
    abstention = call(route(empty, "/api/v1/chat"), api.ChatRequest(question="unknown"))
    assert abstention.answer_status == "insufficient_evidence"
    assert abstention.sources == []


def test_chat_validates_input():
    app = api.create_app(Settings(), fetcher=lambda _: RECORDS)
    with pytest.raises(ValueError):
        api.ChatRequest(question="ok", top_k=100)
    with pytest.raises(HTTPException) as blank:
        call(route(app, "/api/v1/chat"), api.ChatRequest(question="  "))
    assert blank.value.status_code == 422
