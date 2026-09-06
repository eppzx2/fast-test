"""Tests for FAST threat-intelligence feed fetchers."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from core import fetchers

live_feed = pytest.mark.skipif(
    os.getenv("FAST_LIVE_FEEDS") != "1",
    reason="set FAST_LIVE_FEEDS=1 to exercise external providers",
)


@live_feed
def test_fetch_feodo_returns_list():
    assert isinstance(fetchers.fetch_feodo(), list)


@live_feed
def test_fetch_urlhaus_returns_list():
    assert isinstance(fetchers.fetch_urlhaus(), list)


@live_feed
def test_fetch_malwarebazaar_returns_list():
    assert isinstance(fetchers.fetch_malwarebazaar(), list)


@live_feed
def test_fetch_spamhaus_returns_list():
    result = fetchers.fetch_spamhaus()
    assert isinstance(result, list)
    for item in result:
        assert isinstance(item, dict)
        assert "cidr" in item


@live_feed
def test_fetch_all_feeds_returns_all_names():
    result = fetchers.fetch_all_feeds()
    assert set(result) == {"feodo", "urlhaus", "malwarebazaar", "spamhaus"}
    assert all(isinstance(items, list) for items in result.values())


def test_fetch_feodo_success_mocked():
    response = MagicMock()
    response.json.return_value = {
        "data": [{"ip_address": "1.2.3.4", "botnet": "dridex", "last_dns_query": "2024-01-15"}]
    }
    response.raise_for_status = MagicMock()
    with patch("core.fetchers.requests.get", return_value=response):
        result = fetchers.fetch_feodo()
    assert result[0]["ip_address"] == "1.2.3.4"


def test_fetch_feodo_network_error_mocked():
    with patch("core.fetchers.requests.get", side_effect=requests.ConnectionError()):
        assert fetchers.fetch_feodo() == []


def test_fetch_feodo_timeout_mocked():
    with patch("core.fetchers.requests.get", side_effect=requests.Timeout()):
        assert fetchers.fetch_feodo() == []


def test_fetch_urlhaus_legacy_success_mocked(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    response = MagicMock()
    response.text = (
        "# comment\n"
        '# id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\n'
        '"1","2024-01-15 10:00:00","http://evil.com/m.exe","online","malware_download","exe","link","abuse_ch"\n'
    )
    response.raise_for_status = MagicMock()
    with patch("core.fetchers.requests.get", return_value=response) as request_get:
        result = fetchers.fetch_urlhaus()
    assert result[0]["url"] == "http://evil.com/m.exe"
    assert "urlhaus.abuse.ch/downloads" in request_get.call_args.args[0]


def test_fetch_urlhaus_uses_current_api_when_key_present(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    response = MagicMock()
    response.text = (
        '# id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\n'
        '"1","2024-01-15 10:00:00","http://evil.test/a","online","malware_download","","link","x"\n'
    )
    response.raise_for_status = MagicMock()
    with patch("core.fetchers.requests.get", return_value=response) as request_get:
        result = fetchers.fetch_urlhaus()
    assert result[0]["url"] == "http://evil.test/a"
    assert "test-key" in request_get.call_args.args[0]


def test_fetch_urlhaus_http_error_mocked(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    response = MagicMock()
    response.raise_for_status.side_effect = requests.HTTPError(response=MagicMock(status_code=403))
    with patch("core.fetchers.requests.get", return_value=response):
        assert fetchers.fetch_urlhaus() == []


def test_fetch_malwarebazaar_legacy_success_mocked(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    response = MagicMock()
    response.text = (
        '# "first_seen_utc","sha256_hash","md5_hash","file_name","file_type_guess","signature"\n'
        '"2024-01-15 10:00:00","abc123","def456","malware.exe","exe","TrojanX"\n'
    )
    response.raise_for_status = MagicMock()
    with patch("core.fetchers.requests.get", return_value=response):
        result = fetchers.fetch_malwarebazaar()
    assert result[0]["sha256_hash"] == "abc123"


def test_fetch_malwarebazaar_authenticated_api(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "secret-test-key")
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "a" * 64,
                "md5_hash": "b" * 32,
                "first_seen": "2026-09-06 10:00:00",
                "file_name": "sample.exe",
            }
        ],
    }
    with patch("core.fetchers.requests.post", return_value=response) as request_post:
        result = fetchers.fetch_malwarebazaar()
    assert result[0]["sha256_hash"] == "a" * 64
    kwargs = request_post.call_args.kwargs
    assert kwargs["headers"]["Auth-Key"] == "secret-test-key"
    assert kwargs["data"] == {"query": "get_recent", "selector": "100"}


def test_fetch_malwarebazaar_api_status_failure(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "bad-key")
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {"query_status": "no_api_key"}
    with patch("core.fetchers.requests.post", return_value=response):
        assert fetchers.fetch_malwarebazaar() == []


def test_fetch_spamhaus_current_ndjson_mocked():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.text = "\n".join(
        [
            json.dumps({"cidr": "1.10.16.0/20", "sblid": "SBL123"}),
            json.dumps({"cidr": "2.56.192.0/22", "sblid": "SBL456"}),
            json.dumps({"type": "metadata", "timestamp": 123456789}),
        ]
    )
    with patch("core.fetchers.requests.get", return_value=response):
        result = fetchers.fetch_spamhaus()
    assert result == [
        {"cidr": "1.10.16.0/20", "reason": "SBL123"},
        {"cidr": "2.56.192.0/22", "reason": "SBL456"},
    ]


def test_fetch_spamhaus_skips_bad_json_line():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.text = 'not-json\n{"cidr":"1.2.3.0/24","sblid":"SBL1"}\n'
    with patch("core.fetchers.requests.get", return_value=response):
        result = fetchers.fetch_spamhaus()
    assert result == [{"cidr": "1.2.3.0/24", "reason": "SBL1"}]


def test_fetch_all_feeds_partial_failure_isolated(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    with patch.object(fetchers, "fetch_feodo", return_value=[]), \
         patch.object(fetchers, "fetch_urlhaus", return_value=[{"url": "x"}]), \
         patch.object(fetchers, "fetch_malwarebazaar", return_value=[]), \
         patch.object(fetchers, "fetch_spamhaus", return_value=[{"cidr": "1.2.3.0/24"}]):
        result = fetchers.fetch_all_feeds()
    assert result["feodo"] == []
    assert len(result["urlhaus"]) == 1
    assert len(result["spamhaus"]) == 1
