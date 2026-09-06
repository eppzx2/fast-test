"""Normalize provider-specific threat-intelligence records into FAST's schema."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _parse_date(value: Optional[str]) -> str:
    """Return an ISO-8601 UTC timestamp for common provider date formats."""
    if not value:
        return datetime.now(timezone.utc).isoformat()

    value = str(value).strip()
    # Handle already-ISO timestamps, including Z/offset forms, first.
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.isoformat()
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue

    logger.warning("Could not parse date %r; using current UTC time", value)
    return datetime.now(timezone.utc).isoformat()


def normalize_feodo(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for raw in raw_iocs:
        try:
            value = str(raw.get("ip_address") or "").strip()
            if not value:
                logger.warning("Feodo: skipped record without ip_address")
                continue
            tags = [
                str(item)
                for item in (raw.get("botnet"), raw.get("malware"))
                if item
            ]
            seen = _parse_date(raw.get("last_dns_query") or raw.get("last_online"))
            normalized.append(
                {
                    "ioc_value": value,
                    "ioc_type": "ip",
                    "source_feed": "feodo",
                    "first_seen": seen,
                    "last_seen": seen,
                    "tags": tags,
                }
            )
        except Exception as exc:
            logger.error("Feodo normalization error (record skipped): %s", exc)
    logger.info("Feodo: %d/%d records normalized", len(normalized), len(raw_iocs))
    return normalized


def normalize_urlhaus(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for raw in raw_iocs:
        try:
            value = str(raw.get("url") or "").strip()
            if not value:
                logger.warning("URLhaus: skipped record without url")
                continue
            tags: List[str] = []
            if raw.get("threat"):
                tags.append(str(raw["threat"]))
            if raw.get("tags"):
                tags.extend(
                    tag.strip()
                    for tag in str(raw["tags"]).split(",")
                    if tag.strip()
                )
            seen = _parse_date(raw.get("dateadded"))
            normalized.append(
                {
                    "ioc_value": value,
                    "ioc_type": "url",
                    "source_feed": "urlhaus",
                    "first_seen": seen,
                    "last_seen": seen,
                    "tags": tags,
                }
            )
        except Exception as exc:
            logger.error("URLhaus normalization error (record skipped): %s", exc)
    logger.info("URLhaus: %d/%d records normalized", len(normalized), len(raw_iocs))
    return normalized


def normalize_malwarebazaar(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for raw in raw_iocs:
        try:
            value = str(raw.get("sha256_hash") or raw.get("md5_hash") or "").strip()
            if not value:
                logger.warning("MalwareBazaar: skipped record without hash")
                continue
            tags = [
                str(item)
                for item in (
                    raw.get("signature"),
                    raw.get("file_name"),
                    raw.get("file_type_guess") or raw.get("file_type"),
                )
                if item
            ]
            # Current Community API uses first_seen; historical CSV used
            # first_seen_utc. Support both so the normalizer is provider-version safe.
            seen = _parse_date(raw.get("first_seen") or raw.get("first_seen_utc"))
            normalized.append(
                {
                    "ioc_value": value,
                    "ioc_type": "hash",
                    "source_feed": "malwarebazaar",
                    "first_seen": seen,
                    "last_seen": seen,
                    "tags": tags,
                }
            )
        except Exception as exc:
            logger.error("MalwareBazaar normalization error (record skipped): %s", exc)
    logger.info(
        "MalwareBazaar: %d/%d records normalized", len(normalized), len(raw_iocs)
    )
    return normalized


def normalize_spamhaus(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for raw in raw_iocs:
        try:
            value = str(raw.get("cidr") or "").strip()
            if not value:
                logger.warning("Spamhaus: skipped record without cidr")
                continue
            tags = [str(raw["reason"])] if raw.get("reason") else []
            normalized.append(
                {
                    "ioc_value": value,
                    "ioc_type": "ip",
                    "source_feed": "spamhaus",
                    "first_seen": now,
                    "last_seen": now,
                    "tags": tags,
                }
            )
        except Exception as exc:
            logger.error("Spamhaus normalization error (record skipped): %s", exc)
    logger.info("Spamhaus: %d/%d records normalized", len(normalized), len(raw_iocs))
    return normalized


def normalize_all(raw_feeds: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    functions = {
        "feodo": normalize_feodo,
        "urlhaus": normalize_urlhaus,
        "malwarebazaar": normalize_malwarebazaar,
        "spamhaus": normalize_spamhaus,
    }
    all_normalized: List[Dict[str, Any]] = []
    for feed_name, raw_iocs in raw_feeds.items():
        normalizer = functions.get(feed_name)
        if normalizer is None:
            logger.warning("Unknown feed %r; skipped", feed_name)
            continue
        try:
            all_normalized.extend(normalizer(raw_iocs))
        except Exception as exc:
            logger.exception("Normalizer failed for %s: %s", feed_name, exc)
    logger.info("Normalized %d IOCs from %d feeds", len(all_normalized), len(raw_feeds))
    return all_normalized
