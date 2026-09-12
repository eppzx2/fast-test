"""Tests for analyst state, correlation, audit trail and asset risk."""

from core import security_ops


def _use_tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(security_ops, "OPS_DB_PATH", str(tmp_path / "ops.db"))


def test_incident_state_and_audit_round_trip(tmp_path, monkeypatch):
    _use_tmp_db(tmp_path, monkeypatch)
    state = security_ops.update_incident_state(
        "alert-1",
        status="investigating",
        assignee="alice",
        notes="Checking SSH source",
        actor="alice",
    )
    assert state["status"] == "investigating"
    stored = security_ops.get_incident_states(["alert-1"])["alert-1"]
    assert stored["assignee"] == "alice"

    security_ops.audit_event(
        "incident.update",
        actor="alice",
        role="analyst",
        object_type="wazuh_alert",
        object_id="alert-1",
    )
    events = security_ops.list_audit_events(10)
    assert events[0]["action"] == "incident.update"
    assert events[0]["object_id"] == "alert-1"


def test_build_cases_preserves_real_alert_and_defaults(tmp_path, monkeypatch):
    _use_tmp_db(tmp_path, monkeypatch)
    alerts = [{"event_id": "a1", "level": 12, "rule_id": "100221", "agent_id": "001"}]
    cases = security_ops.build_incident_cases(alerts)
    assert cases[0]["event_id"] == "a1"
    assert cases[0]["case_id"] == "a1"
    assert cases[0]["priority"] == "critical"
    assert cases[0]["status"] == "new"


def test_correlation_requires_multiple_real_events():
    single = [{"event_id": "a1", "timestamp": "2026-09-12T12:00:00Z", "agent_id": "001", "source_ip": "192.0.2.1", "rule_id": "100200", "level": 10, "attack_type": "SSH brute-force"}]
    assert security_ops.correlate_alerts(single) == []
    correlated = security_ops.correlate_alerts(single + [{"event_id": "a2", "timestamp": "2026-09-12T12:05:00Z", "agent_id": "001", "source_ip": "192.0.2.1", "rule_id": "100211", "level": 7, "attack_type": "Port scan"}])
    assert len(correlated) == 1
    assert correlated[0]["event_count"] == 2
    assert correlated[0]["rule_ids"] == ["100200", "100211"]
    assert correlated[0]["title"] == "Multi-stage FAST activity"


def test_asset_risk_uses_agent_health_and_real_fast_alerts():
    agents = [
        {"id": "001", "hostname": "target", "status": "active"},
        {"id": "002", "hostname": "offline", "status": "disconnected"},
    ]
    alerts = [
        {"event_id": "a1", "agent_id": "001", "rule_id": "100221", "level": 12},
        {"event_id": "a2", "agent_id": "001", "rule_id": "100200", "level": 10},
    ]
    result = security_ops.calculate_asset_risk(agents, alerts)
    by_id = {item["id"]: item for item in result}
    assert by_id["001"]["risk_score"] > by_id["002"]["risk_score"]
    assert by_id["001"]["alert_count"] == 2
    assert by_id["002"]["risk_score"] == 25
