"""Exact detection-health aggregation tests."""

from core.wazuh_client import WazuhClient


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.text = ""

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return FakeResponse(self.payload)


def test_rule_activity_returns_exact_bucket_counts(monkeypatch):
    monkeypatch.setenv("FAST_WAZUH_INDEXER_URL", "https://indexer:9200")
    payload = {
        "aggregations": {
            "by_rule": {
                "buckets": [
                    {
                        "key": "100200",
                        "doc_count": 6,
                        "latest": {
                            "hits": {
                                "hits": [
                                    {
                                        "_source": {
                                            "timestamp": "2026-09-12T12:00:00Z",
                                            "agent": {"id": "001", "name": "target"},
                                        }
                                    }
                                ]
                            }
                        },
                    }
                ]
            }
        }
    }
    session = FakeSession(payload)
    result = WazuhClient(session=session).rule_activity(rule_ids=["100200", "100211"], minutes=1440)
    by_rule = {item["rule_id"]: item for item in result["items"]}
    assert by_rule["100200"]["count"] == 6
    assert by_rule["100200"]["last_agent"] == "target"
    assert by_rule["100211"]["count"] == 0
    body = session.calls[0][2]["json"]
    assert body["size"] == 0
    assert "by_rule" in body["aggs"]
