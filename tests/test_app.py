"""Web dashboard safety/health regression tests."""

from unittest.mock import patch

import app as webapp
from core import db


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "web-test.db"))
    webapp.app.config.update(TESTING=True)
    return webapp.app.test_client()


def test_health_endpoint_and_security_headers(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["service"] == "fast-ioc-collector-web"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_fetch_returns_503_when_all_feeds_are_empty(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    empty = {"feodo": [], "urlhaus": [], "malwarebazaar": [], "spamhaus": []}
    with patch("app.fetchers.fetch_all_feeds", return_value=empty):
        response = client.post("/api/fetch")
    assert response.status_code == 503
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["raw_counts"] == {name: 0 for name in empty}


def test_ui_config_exposes_only_non_secret_dashboard_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("FAST_WAZUH_DASHBOARD_URL", "https://100.64.0.10")
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "must-not-leak")
    client = _client(tmp_path, monkeypatch)

    response = client.get("/api/ui-config")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["product_name"] == "FAST"
    assert payload["wazuh_dashboard_url"] == "https://100.64.0.10"
    assert "ABUSECH_AUTH_KEY" not in payload
    assert "must-not-leak" not in response.get_data(as_text=True)


def test_detection_catalogue_matches_current_fast_rule_ids(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.get("/api/detections")
    assert response.status_code == 200
    payload = response.get_json()
    assert [item["id"] for item in payload["items"]] == ["100200", "100211", "100221"]
    assert payload["total"] == 3


def test_ioc_endpoint_supports_minimum_confidence_filter(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    rows = [
        {"ioc_value": "192.0.2.1", "ioc_type": "ip", "source_feed": "feodo", "confidence_score": 25, "last_seen": "2026-09-08T00:00:00+00:00"},
        {"ioc_value": "198.51.100.2", "ioc_type": "ip", "source_feed": "spamhaus", "confidence_score": 75, "last_seen": "2026-09-08T00:00:00+00:00"},
        {"ioc_value": "203.0.113.3", "ioc_type": "ip", "source_feed": "feodo,spamhaus", "confidence_score": 100, "last_seen": "2026-09-08T00:00:00+00:00"},
    ]
    with patch("app.db.get_all_iocs", return_value=rows):
        response = client.get("/api/iocs?min_score=75")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total"] == 2
    assert [item["confidence_score"] for item in payload["items"]] == [75, 100]


def test_debug_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("FAST_WEB_DEBUG", raising=False)
    assert webapp._env_bool("FAST_WEB_DEBUG", False) is False
    monkeypatch.setenv("FAST_WEB_DEBUG", "1")
    assert webapp._env_bool("FAST_WEB_DEBUG", False) is True
