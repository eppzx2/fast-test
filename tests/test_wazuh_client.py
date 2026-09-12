"""Unit tests for the read-only Wazuh integration."""

from core.wazuh_client import WazuhClient


class FakeResponse:
    def __init__(self, payload=None, text="", status=200):
        self._payload = payload
        self.text = text
        self.status_code = status

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"status {self.status_code}")


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def test_list_agents_returns_normalized_live_asset_fields(monkeypatch):
    monkeypatch.setenv("FAST_WAZUH_API_URL", "https://manager:55000")
    session = FakeSession(
        [
            FakeResponse(text="jwt-token"),
            FakeResponse(
                {
                    "data": {
                        "affected_items": [
                            {
                                "id": "001",
                                "name": "ebi-VMware",
                                "ip": "100.64.0.20",
                                "status": "active",
                                "os": {"name": "Ubuntu", "version": "24.04", "platform": "ubuntu"},
                                "version": "Wazuh v4.9.0",
                                "lastKeepAlive": "2026-09-12T12:00:00Z",
                            }
                        ],
                        "total_affected_items": 1,
                    }
                }
            ),
        ]
    )
    client = WazuhClient(session=session)
    result = client.list_agents()

    assert result["source"] == "wazuh-server-api"
    assert result["total"] == 1
    assert result["items"][0]["hostname"] == "ebi-VMware"
    assert result["items"][0]["os"] == "Ubuntu"
    assert result["items"][0]["status"] == "active"
    assert session.calls[0][0] == "POST"
    assert session.calls[1][1].endswith("/agents")


def test_recent_alerts_reads_fast_rules_from_indexer(monkeypatch):
    monkeypatch.setenv("FAST_WAZUH_INDEXER_URL", "https://indexer:9200")
    session = FakeSession(
        [
            FakeResponse(
                {
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_id": "alert-1",
                                "_source": {
                                    "timestamp": "2026-09-12T12:05:00Z",
                                    "rule": {"id": "100200", "level": 10, "description": "FAST SSH failed authentication detected"},
                                    "agent": {"id": "001", "name": "ebi-VMware", "ip": "100.64.0.20"},
                                    "data": {"srcip": "100.64.0.30"},
                                },
                            }
                        ],
                    }
                }
            )
        ]
    )
    client = WazuhClient(session=session)
    result = client.recent_alerts(rule_ids=["100200"], limit=10, minutes=15)

    assert result["source"] == "wazuh-indexer"
    assert result["items"][0]["attack_type"] == "SSH brute-force"
    assert result["items"][0]["source_ip"] == "100.64.0.30"
    body = session.calls[0][2]["json"]
    assert body["query"]["bool"]["filter"][1] == {"terms": {"rule.id": ["100200"]}}
    assert session.calls[0][1].endswith("/wazuh-alerts-*/_search")
