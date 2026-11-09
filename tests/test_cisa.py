import pytest
import requests

from cybersecurity_rag.cisa import CISADataError, fetch_vulnerabilities, parse_cisa_payload
from cybersecurity_rag.config import Settings


def record(**changes):
    item = {"cveID": "CVE-2024-12345", "vendorProject": "Acme", "product": "Widget",
            "vulnerabilityName": "Widget flaw", "shortDescription": "A test flaw."}
    item.update(changes)
    return item


def test_parses_valid_records_and_skips_malformed_records():
    with pytest.warns(UserWarning, match="Skipped 2 malformed"):
        parsed = parse_cisa_payload({"vulnerabilities": [record(), None, {"cveID": "missing fields"}]})
    assert [item["cveID"] for item in parsed] == ["CVE-2024-12345"]


@pytest.mark.parametrize("payload", [None, {}, {"vulnerabilities": "bad"}])
def test_rejects_invalid_feed_envelope(payload):
    with pytest.raises(CISADataError):
        parse_cisa_payload(payload)


def test_rejects_nonempty_feed_with_no_valid_records():
    with pytest.warns(UserWarning, match="Skipped 1 malformed"):
        with pytest.raises(CISADataError, match="no usable"):
            parse_cisa_payload({"vulnerabilities": [None]})


def test_empty_catalog_is_rejected():
    with pytest.raises(CISADataError, match="catalog is empty"):
        parse_cisa_payload({"vulnerabilities": []})


def test_malformed_record_warning_reports_count_without_record_data():
    with pytest.warns(UserWarning, match="Skipped 2 malformed") as caught:
        parsed = parse_cisa_payload({"vulnerabilities": [None, {"cveID": "private-record"}, record()]})
    assert len(parsed) == 1
    assert "private-record" not in str(caught[0].message)


def test_duplicate_cves_are_removed_preserving_first_occurrence():
    duplicate = record(vulnerabilityName="Later duplicate")
    other = record(cveID="CVE-2023-54321")
    parsed = parse_cisa_payload({"vulnerabilities": [record(), duplicate, other]})
    assert [item["cveID"] for item in parsed] == ["CVE-2024-12345", "CVE-2023-54321"]
    assert parsed[0]["vulnerabilityName"] == "Widget flaw"


def test_fetch_and_parse_end_to_end_with_mocked_response():
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"vulnerabilities": [record(), record()]}

    class Client:
        def get(self, url, timeout):
            assert "cisa.gov" in url
            assert timeout == 30.0
            return Response()

    parsed = fetch_vulnerabilities(session=Client())
    assert len(parsed) == 1
    assert parsed[0]["cveID"] == "CVE-2024-12345"


def test_fetch_reports_timeout_without_exposing_request_details():
    class Client:
        def get(self, *args, **kwargs):
            raise requests.Timeout("sensitive URL details")

    with pytest.raises(CISADataError, match="Timed out") as error:
        fetch_vulnerabilities(Settings("unused"), Client())
    assert "sensitive" not in str(error.value)


def test_fetch_reports_connection_failure():
    class Client:
        def get(self, *args, **kwargs):
            raise requests.ConnectionError("private connection detail")

    with pytest.raises(CISADataError, match="Could not connect") as error:
        fetch_vulnerabilities(Settings("unused"), Client())
    assert "private" not in str(error.value)


def test_fetch_validates_http_status():
    class Response:
        def raise_for_status(self):
            raise requests.HTTPError("private response details")

    class Client:
        def get(self, *args, **kwargs):
            return Response()

    with pytest.raises(CISADataError, match="Could not fetch") as error:
        fetch_vulnerabilities(Settings("unused"), Client())
    assert "private" not in str(error.value)


def test_fetch_rejects_invalid_json():
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            raise ValueError("not json")

    class Client:
        def get(self, *args, **kwargs):
            return Response()

    with pytest.raises(CISADataError, match="invalid JSON"):
        fetch_vulnerabilities(Settings("unused"), Client())
