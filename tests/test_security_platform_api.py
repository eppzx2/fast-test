"""Security-operations API integration regression tests."""

from unittest.mock import patch

import app as webapp
from core import db, security_ops


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("FAST_AUTH_ENABLED", "0")
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "platform-ioc.db"))
    monkeypatch.setattr(security_ops, "OPS_DB_PATH", str(tmp_path / "platform-ops.db"))
    webapp.app.config.update(TESTING=True)
    return webapp.app.test_client()


def test_index_injects_security_operations_assets(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    text = client.get("/").get_data(as_text=True)
    assert "/static/fast-platform.js" in text
    assert "/static/security-ops.js" in text
    assert "/static/security-ops.css" in text


def test_security_asset_risk_endpoint_uses_live_wazuh_data(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    with patch("core.platform_api.get_wazuh_client") as factory:
        factory.return_value.list_agents.return_value = {
            "items": [{"id": "001", "hostname": "target", "status": "active"}],
            "total": 1,
        }
        factory.return_value.recent_alerts.return_value = {
            "items": [{"event_id": "a1", "agent_id": "001", "rule_id": "100221", "level": 12}],
            "total": 1,
            "sampled": False,
        }
        response = client.get("/api/security/assets")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["items"][0]["hostname"] == "target"
    assert payload["items"][0]["risk_score"] > 0


def test_detection_health_uses_exact_rule_activity(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    with patch("core.platform_api.get_wazuh_client") as factory:
        factory.return_value.rule_activity.return_value = {
            "items": [{"rule_id": "100200", "count": 5, "last_triggered": "2026-09-12T12:00:00Z", "last_agent": "target"}]
        }
        factory.return_value.list_agents.return_value = {
            "items": [{"id": "001", "status": "active"}]
        }
        response = client.get("/api/security/detections")
    assert response.status_code == 200
    by_id = {item["id"]: item for item in response.get_json()["items"]}
    assert by_id["100200"]["alerts_24h"] == 5
    assert by_id["100200"]["active_agents"] == 1
