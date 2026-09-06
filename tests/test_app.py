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
    assert response.get_json()["status"] == "ok"
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


def test_debug_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("FAST_WEB_DEBUG", raising=False)
    assert webapp._env_bool("FAST_WEB_DEBUG", False) is False
    monkeypatch.setenv("FAST_WEB_DEBUG", "1")
    assert webapp._env_bool("FAST_WEB_DEBUG", False) is True
