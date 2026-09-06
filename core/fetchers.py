"""Threat-intelligence feed fetchers used by FAST.

The collector intentionally treats individual feed failures as non-fatal so one
provider outage cannot stop the remaining feeds. Callers can inspect the
returned per-feed lists and decide whether an all-feed failure is fatal.
"""

import csv
import json
import logging
import os
from typing import Any, Dict, List

import requests

logger = logging.getLogger(__name__)

USER_AGENT = "FAST-IOC-Collector/1.0 (+https://github.com/eppzx2/fast-test)"
REQUEST_TIMEOUT = 20

FEED_URLS = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    # Compatibility dump. When ABUSECH_AUTH_KEY is set, URLhaus uses its
    # current authenticated export endpoint instead.
    "urlhaus_legacy": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "urlhaus_api": "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv",
    # MalwareBazaar's current Community API requires an Auth-Key. The legacy
    # CSV URL is retained only as a best-effort compatibility fallback.
    "malwarebazaar_api": "https://mb-api.abuse.ch/api/v1/",
    "malwarebazaar_legacy": "https://bazaar.abuse.ch/export/csv/recent/",
    # Spamhaus recommends the JSON DROP dataset; the old text file is legacy.
    "spamhaus": "https://www.spamhaus.org/drop/drop_v4.json",
}


def _headers() -> Dict[str, str]:
    return {"User-Agent": USER_AGENT}


def _abusech_auth_key() -> str:
    return os.getenv("ABUSECH_AUTH_KEY", "").strip()


def _parse_commented_csv(text: str, default_fieldnames: List[str]) -> List[Dict[str, Any]]:
    """Parse abuse.ch-style CSV files whose header is prefixed with '#'."""
    lines = text.splitlines()
    data_lines = [line for line in lines if line and not line.startswith("#")]
    if not data_lines:
        return []

    header_line = None
    for line in lines:
        stripped = line.lstrip("# ").strip()
        if not stripped:
            continue
        # Headers used by URLhaus/MalwareBazaar begin with id/first_seen.
        lowered = stripped.lower().lstrip('"')
        if lowered.startswith("id,") or lowered.startswith("first_seen"):
            header_line = stripped
            break

    if header_line:
        # Use csv.reader rather than split(',') so quoted headers remain safe.
        fieldnames = [h.strip().strip('"') for h in next(csv.reader([header_line]))]
    else:
        fieldnames = default_fieldnames

    reader = csv.DictReader(data_lines, fieldnames=fieldnames, skipinitialspace=True)
    parsed: List[Dict[str, Any]] = []
    for row in reader:
        parsed.append(
            {
                key: (value.strip().strip('"') if isinstance(value, str) else value)
                for key, value in row.items()
                if key is not None
            }
        )
    return parsed


def fetch_feodo() -> List[Dict[str, Any]]:
    """Fetch Feodo Tracker botnet C2 IPs."""
    url = FEED_URLS["feodo"]
    try:
        logger.info("Fetching Feodo Tracker: %s", url)
        response = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            result = payload["data"]
        elif isinstance(payload, list):
            result = payload
        else:
            logger.warning("Feodo: unexpected JSON structure")
            return []
        logger.info("Feodo: %d records fetched", len(result))
        return result
    except requests.RequestException as exc:
        logger.error("Feodo Tracker request failed: %s", exc)
    except (ValueError, TypeError) as exc:
        logger.error("Feodo Tracker parse failed: %s", exc)
    return []


def fetch_urlhaus() -> List[Dict[str, Any]]:
    """Fetch recent malicious URLs from URLhaus.

    Current URLhaus Community API exports require an Auth-Key. FAST uses that
    endpoint whenever ABUSECH_AUTH_KEY is configured and otherwise retains the
    historical CSV endpoint as a compatibility fallback.
    """
    auth_key = _abusech_auth_key()
    if auth_key:
        url = FEED_URLS["urlhaus_api"].format(auth_key=auth_key)
    else:
        url = FEED_URLS["urlhaus_legacy"]
        logger.warning(
            "URLhaus: ABUSECH_AUTH_KEY is not set; using the legacy CSV compatibility endpoint"
        )

    try:
        logger.info("Fetching URLhaus: %s", url.replace(auth_key, "***") if auth_key else url)
        response = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        result = _parse_commented_csv(
            response.text,
            [
                "id",
                "dateadded",
                "url",
                "url_status",
                "last_online",
                "threat",
                "tags",
                "urlhaus_link",
                "reporter",
            ],
        )
        logger.info("URLhaus: %d records fetched", len(result))
        return result
    except requests.RequestException as exc:
        logger.error("URLhaus request failed: %s", exc)
    except (csv.Error, ValueError, TypeError) as exc:
        logger.error("URLhaus parse failed: %s", exc)
    return []


def _fetch_malwarebazaar_api(auth_key: str) -> List[Dict[str, Any]]:
    response = requests.post(
        FEED_URLS["malwarebazaar_api"],
        headers={**_headers(), "Auth-Key": auth_key},
        data={"query": "get_recent", "selector": "100"},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("unexpected JSON response")
    status = payload.get("query_status")
    if status == "no_results":
        return []
    if status != "ok":
        raise ValueError(f"API query_status={status!r}")
    data = payload.get("data", [])
    if not isinstance(data, list):
        raise ValueError("API 'data' is not a list")
    return data


def _fetch_malwarebazaar_legacy() -> List[Dict[str, Any]]:
    response = requests.get(
        FEED_URLS["malwarebazaar_legacy"], headers=_headers(), timeout=REQUEST_TIMEOUT
    )
    response.raise_for_status()
    return _parse_commented_csv(
        response.text,
        [
            "first_seen_utc",
            "sha256_hash",
            "md5_hash",
            "sha1_hash",
            "reporter",
            "file_name",
            "file_type_guess",
            "mime_type",
            "signature",
            "clamav",
            "vtpercent",
            "imphash",
            "ssdeep",
            "tlsh",
        ],
    )


def fetch_malwarebazaar() -> List[Dict[str, Any]]:
    """Fetch the latest MalwareBazaar samples.

    Set ABUSECH_AUTH_KEY to use the supported Community API. Without a key,
    FAST attempts the old CSV export for backward compatibility, but that
    endpoint is not relied upon for correctness and may be unavailable.
    """
    auth_key = _abusech_auth_key()
    try:
        if auth_key:
            logger.info("Fetching MalwareBazaar via authenticated Community API")
            result = _fetch_malwarebazaar_api(auth_key)
        else:
            logger.warning(
                "MalwareBazaar: ABUSECH_AUTH_KEY is not set; trying legacy CSV fallback. "
                "Set a free abuse.ch Auth-Key for the supported API."
            )
            result = _fetch_malwarebazaar_legacy()
        logger.info("MalwareBazaar: %d records fetched", len(result))
        return result
    except requests.RequestException as exc:
        logger.error("MalwareBazaar request failed: %s", exc)
    except (ValueError, csv.Error, TypeError) as exc:
        logger.error("MalwareBazaar parse/API failed: %s", exc)
    return []


def fetch_spamhaus() -> List[Dict[str, Any]]:
    """Fetch Spamhaus DROP IPv4 ranges from the current NDJSON dataset."""
    url = FEED_URLS["spamhaus"]
    try:
        logger.info("Fetching Spamhaus DROP: %s", url)
        response = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        result: List[Dict[str, Any]] = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("Spamhaus: skipping malformed JSON line: %s", exc)
                continue
            if not isinstance(item, dict) or not item.get("cidr"):
                # The final metadata object contains timestamp/copyright but no CIDR.
                continue
            result.append(
                {
                    "cidr": str(item["cidr"]).strip(),
                    "reason": str(item.get("sblid") or item.get("reason") or "").strip(),
                }
            )
        logger.info("Spamhaus: %d records fetched", len(result))
        return result
    except requests.RequestException as exc:
        logger.error("Spamhaus request failed: %s", exc)
    except (ValueError, TypeError) as exc:
        logger.error("Spamhaus parse failed: %s", exc)
    return []


def fetch_all_feeds() -> Dict[str, List[Dict[str, Any]]]:
    """Fetch every configured feed independently and return all results."""
    fetch_functions = {
        "feodo": fetch_feodo,
        "urlhaus": fetch_urlhaus,
        "malwarebazaar": fetch_malwarebazaar,
        "spamhaus": fetch_spamhaus,
    }
    results: Dict[str, List[Dict[str, Any]]] = {}
    for feed_name, fetch_func in fetch_functions.items():
        try:
            results[feed_name] = fetch_func()
        except Exception as exc:  # final isolation boundary between providers
            logger.exception("Unexpected failure in feed '%s': %s", feed_name, exc)
            results[feed_name] = []

    total = sum(len(items) for items in results.values())
    failed = [name for name, items in results.items() if not items]
    logger.info("All feeds complete: %d raw records", total)
    if failed:
        logger.warning("Feeds with zero records: %s", ", ".join(failed))
    return results
