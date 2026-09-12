"""Regression tests for FAST platform UI endpoints and additive assets."""

from unittest.mock import patch

import app as webapp
from core import db


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "platform-web.db"))
    webapp.app.config.update(TESTING=True)
    return webapp.app.test_client()


def test_index_injects_additive_platform_assets(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.get("/")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "/static/fast-platform.css" in text
    assert "/static/fast-platform.js" in text


def test_asset_catalog_endpoint_uses_live_wazuh_client(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    result = {"source": "wazuh-server-api", "items": [{"id": "001", "hostname": "target"}], "total": 1}
    with patch("core.platform_api.get_wazuh_client") as factory:
        factory.return_value.list_agents.return_value = result
        response = client.get("/api/wazuh/assets")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["items"][0]["hostname"] == "target"


def test_live_alert_endpoint_restricts_rule_scope(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    result = {"source": "wazuh-indexer", "items": [], "total": 0, "window_minutes": 20, "rule_ids": ["100200"]}
    with patch("core.platform_api.get_wazuh_client") as factory:
        factory.return_value.recent_alerts.return_value = result
        response = client.get("/api/wazuh/alerts?minutes=20&rules=100200,999999")
        kwargs = factory.return_value.recent_alerts.call_args.kwargs
    assert response.status_code == 200
    assert kwargs["rule_ids"] == ["100200"]
    assert kwargs["minutes"] == 20
