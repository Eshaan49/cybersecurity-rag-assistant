"""Fetch and validate the CISA Known Exploited Vulnerabilities feed."""

import warnings

import requests


class CISADataError(RuntimeError):
    """Raised when the CISA feed cannot be fetched or validated."""


DEFAULT_CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUIRED_FIELDS = ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription")


def parse_cisa_payload(payload):
    """Return usable, unique records and warn about malformed catalog entries."""
    if not isinstance(payload, dict):
        raise CISADataError("CISA response must be a JSON object.")
    records = payload.get("vulnerabilities")
    if not isinstance(records, list):
        raise CISADataError("CISA response is missing a vulnerabilities list.")

    valid = []
    seen_cves = set()
    malformed_count = 0
    for item in records:
        if not isinstance(item, dict):
            malformed_count += 1
            continue
        if any(not isinstance(item.get(field), str) or not item[field].strip() for field in REQUIRED_FIELDS):
            malformed_count += 1
            continue
        cve_id = item["cveID"].strip().upper()
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        valid.append(item)
    if malformed_count:
        warnings.warn(
            f"Skipped {malformed_count} malformed CISA vulnerability record(s).",
            UserWarning,
            stacklevel=2,
        )
    if not valid:
        if not records:
            raise CISADataError("CISA vulnerability catalog is empty.")
        raise CISADataError("CISA response contains no usable vulnerability records.")
    return valid


def fetch_vulnerabilities(settings=None, session=None):
    """Fetch the feed and return validated records without import-time I/O."""
    url = settings.cisa_url if settings else DEFAULT_CISA_URL
    timeout = settings.request_timeout if settings else 30.0
    client = session or requests
    try:
        response = client.get(url, timeout=timeout)
        response.raise_for_status()
    except requests.Timeout as exc:
        raise CISADataError("Timed out while fetching the CISA KEV feed.") from exc
    except requests.ConnectionError as exc:
        raise CISADataError("Could not connect to the CISA KEV feed.") from exc
    except requests.RequestException as exc:
        raise CISADataError("Could not fetch the CISA KEV feed.") from exc
    try:
        payload = response.json()
    except (ValueError, requests.JSONDecodeError) as exc:
        raise CISADataError("CISA returned invalid JSON.") from exc
    return parse_cisa_payload(payload)
