"""MITRE ATT&CK API integration tests."""

from unittest.mock import patch

import app as webapp
from core import db


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "mitre-web.db"))
    webapp.app.config.update(TESTING=True)
    return webapp.app.test_client()


def test_index_injects_mitre_assets(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.get("/")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "/static/mitre.css" in text
    assert "/static/mitre.js" in text


def test_mitre_endpoint_uses_live_wazuh_activity(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    activity = {
        "source": "wazuh-indexer",
        "items": [
            {"rule_id": "100200", "count": 3, "last_triggered": "2026-09-13T12:00:00Z", "last_agent": "ebi-VMware"},
            {"rule_id": "100211", "count": 0, "last_triggered": "", "last_agent": ""},
            {"rule_id": "100221", "count": 0, "last_triggered": "", "last_agent": ""},
        ],
    }
    with patch("core.platform_api.get_wazuh_client") as factory:
        factory.return_value.rule_activity.return_value = activity
        response = client.get("/api/security/mitre?minutes=1440")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["framework"] == "MITRE ATT&CK Enterprise"
    assert payload["summary"]["mapped_tactics"] == 4
    assert payload["summary"]["observed_tactics"] == 1
    assert payload["summary"]["alerts"] == 3
    assert any(item["id"] == "T1110" and item["alerts"] == 3 for item in payload["techniques"])
    factory.return_value.rule_activity.assert_called_once_with(
        rule_ids=("100200", "100211", "100221"), minutes=1440
    )


def test_detection_health_includes_named_mitre_mapping(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    with patch("core.platform_api.get_wazuh_client") as factory:
        factory.return_value.rule_activity.return_value = {
            "items": [
                {"rule_id": "100200", "count": 1, "last_triggered": "2026-09-13T12:00:00Z", "last_agent": "target"},
                {"rule_id": "100211", "count": 0, "last_triggered": "", "last_agent": ""},
                {"rule_id": "100221", "count": 0, "last_triggered": "", "last_agent": ""},
            ]
        }
        factory.return_value.list_agents.return_value = {"items": []}
        response = client.get("/api/security/detections")

    assert response.status_code == 200
    first = response.get_json()["items"][0]
    assert first["id"] == "100200"
    assert first["mitre_mapping"]["techniques"][0]["name"] == "Brute Force"
    assert first["mitre_mapping"]["tactics"][0]["name"] == "Credential Access"
