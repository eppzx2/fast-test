"""Tests for FAST IOC normalization."""

from datetime import datetime

from core import normalizer


def _is_utc_iso(value: str) -> bool:
    parsed = datetime.fromisoformat(value)
    return parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0


def test_parse_date_is_consistently_utc():
    assert _is_utc_iso(normalizer._parse_date("2024-01-15"))
    assert _is_utc_iso(normalizer._parse_date("2024-01-15 10:30:00"))
    assert _is_utc_iso(normalizer._parse_date("2024-01-15T10:30:00Z"))
    assert _is_utc_iso(normalizer._parse_date(None))


def test_normalize_feodo():
    raw = [
        {"ip_address": "1.2.3.4", "botnet": "dridex", "last_dns_query": "2024-01-15"},
        {"ip_address": "5.6.7.8", "botnet": "emotet", "last_dns_query": "2024-01-16"},
    ]
    result = normalizer.normalize_feodo(raw)
    assert len(result) == 2
    assert result[0]["ioc_value"] == "1.2.3.4"
    assert result[0]["ioc_type"] == "ip"
    assert result[0]["source_feed"] == "feodo"
    assert "dridex" in result[0]["tags"]
    assert result[0]["first_seen"] == result[0]["last_seen"]
    assert _is_utc_iso(result[0]["first_seen"])


def test_normalize_feodo_missing_ip_skipped():
    result = normalizer.normalize_feodo(
        [
            {"botnet": "dridex", "last_dns_query": "2024-01-15"},
            {"ip_address": "5.6.7.8", "botnet": "emotet", "last_dns_query": "2024-01-16"},
        ]
    )
    assert [item["ioc_value"] for item in result] == ["5.6.7.8"]


def test_normalize_urlhaus():
    result = normalizer.normalize_urlhaus(
        [
            {
                "url": "http://evil.com/malware.exe",
                "dateadded": "2024-01-15 10:30:00",
                "threat": "malware_download",
                "tags": "exe,trojan",
            }
        ]
    )
    assert result[0]["ioc_type"] == "url"
    assert {"malware_download", "exe", "trojan"}.issubset(result[0]["tags"])
    assert _is_utc_iso(result[0]["first_seen"])


def test_normalize_malwarebazaar_legacy_date_field():
    result = normalizer.normalize_malwarebazaar(
        [
            {
                "sha256_hash": "abc123def456",
                "md5_hash": "aaa111",
                "first_seen_utc": "2024-01-15 10:30:00",
                "file_name": "malware.exe",
                "signature": "TrojanX",
            }
        ]
    )
    assert result[0]["ioc_value"] == "abc123def456"
    assert result[0]["ioc_type"] == "hash"
    assert "TrojanX" in result[0]["tags"]
    assert _is_utc_iso(result[0]["first_seen"])


def test_normalize_malwarebazaar_current_api_date_field():
    result = normalizer.normalize_malwarebazaar(
        [
            {
                "sha256_hash": "a" * 64,
                "first_seen": "2026-09-06 10:30:00",
                "file_name": "sample.exe",
                "file_type": "exe",
            }
        ]
    )
    assert result[0]["ioc_value"] == "a" * 64
    assert "sample.exe" in result[0]["tags"]
    assert "exe" in result[0]["tags"]
    assert result[0]["first_seen"].startswith("2026-09-06T10:30:00")
    assert _is_utc_iso(result[0]["first_seen"])


def test_normalize_malwarebazaar_fallback_to_md5():
    result = normalizer.normalize_malwarebazaar(
        [{"md5_hash": "aaa111", "first_seen_utc": "2024-01-15 10:30:00"}]
    )
    assert result[0]["ioc_value"] == "aaa111"


def test_normalize_spamhaus():
    result = normalizer.normalize_spamhaus(
        [
            {"cidr": "192.168.1.0/24", "reason": "SBL12345"},
            {"cidr": "10.0.0.0/8", "reason": ""},
        ]
    )
    assert len(result) == 2
    assert result[0]["ioc_type"] == "ip"
    assert "SBL12345" in result[0]["tags"]
    assert result[1]["tags"] == []
    assert _is_utc_iso(result[0]["first_seen"])


def test_normalize_all():
    raw_feeds = {
        "feodo": [{"ip_address": "1.2.3.4", "last_dns_query": "2024-01-15"}],
        "urlhaus": [{"url": "http://evil.com", "dateadded": "2024-01-15 10:00:00"}],
        "malwarebazaar": [{"sha256_hash": "abc123", "first_seen": "2024-01-15 10:00:00"}],
        "spamhaus": [{"cidr": "192.168.1.0/24", "reason": "test"}],
    }
    result = normalizer.normalize_all(raw_feeds)
    assert len(result) == 4
    assert {item["ioc_type"] for item in result} == {"ip", "url", "hash"}
    assert {item["source_feed"] for item in result} == {
        "feodo",
        "urlhaus",
        "malwarebazaar",
        "spamhaus",
    }


def test_normalize_all_unknown_feed_skipped():
    result = normalizer.normalize_all(
        {
            "unknown_feed": [{"some_field": "some_value"}],
            "feodo": [{"ip_address": "1.2.3.4", "last_dns_query": "2024-01-15"}],
        }
    )
    assert len(result) == 1
    assert result[0]["source_feed"] == "feodo"


def test_normalize_all_empty_input():
    assert normalizer.normalize_all({}) == []
