"""Security-operations state derived from real Wazuh telemetry.

This module deliberately keeps analyst workflow state separate from the IOC
SQLite database. Wazuh remains the source of truth for alerts and agents; FAST
only persists analyst-owned metadata (status, assignee, notes) and an audit
trail.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

OPS_DB_PATH = os.getenv("FAST_OPS_DB_PATH", "fast_operations.db")
INCIDENT_STATUSES = ("new", "investigating", "resolved", "false_positive")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(OPS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_operations_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_state (
                event_id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'new',
                assignee TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                object_type TEXT NOT NULL DEFAULT '',
                object_id TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)"
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def audit_event(
    action: str,
    *,
    actor: str = "system",
    role: str = "system",
    object_type: str = "",
    object_id: str = "",
    details: dict | None = None,
) -> None:
    init_operations_db()
    safe_details = details if isinstance(details, dict) else {}
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_log
                (timestamp, actor, role, action, object_type, object_id, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _now_iso(),
                str(actor)[:120],
                str(role)[:40],
                str(action)[:160],
                str(object_type)[:80],
                str(object_id)[:240],
                json.dumps(safe_details, sort_keys=True)[:8000],
            ),
        )


def list_audit_events(limit: int = 100) -> list[dict]:
    init_operations_db()
    limit = max(1, min(500, int(limit)))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, actor, role, action, object_type, object_id, details_json
            FROM audit_log ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    items = []
    for row in rows:
        try:
            details = json.loads(row["details_json"] or "{}")
        except json.JSONDecodeError:
            details = {}
        items.append(
            {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "actor": row["actor"],
                "role": row["role"],
                "action": row["action"],
                "object_type": row["object_type"],
                "object_id": row["object_id"],
                "details": details,
            }
        )
    return items


def get_incident_states(event_ids: Iterable[str]) -> dict[str, dict]:
    ids = [str(value) for value in event_ids if str(value)]
    if not ids:
        return {}
    init_operations_db()
    placeholders = ",".join("?" for _ in ids)
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM incident_state WHERE event_id IN ({placeholders})", ids
        ).fetchall()
    return {row["event_id"]: dict(row) for row in rows}


def update_incident_state(
    event_id: str,
    *,
    status: str,
    assignee: str = "",
    notes: str = "",
    actor: str,
) -> dict:
    event_id = str(event_id or "").strip()
    status = str(status or "").strip().lower()
    assignee = str(assignee or "").strip()[:120]
    notes = str(notes or "").strip()[:4000]
    if not event_id:
        raise ValueError("event_id is required")
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"Unsupported incident status: {status}")

    updated_at = _now_iso()
    init_operations_db()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO incident_state
                (event_id, status, assignee, notes, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                status = excluded.status,
                assignee = excluded.assignee,
                notes = excluded.notes,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            """,
            (event_id, status, assignee, notes, updated_at, str(actor)[:120]),
        )
    return {
        "event_id": event_id,
        "status": status,
        "assignee": assignee,
        "notes": notes,
        "updated_at": updated_at,
        "updated_by": str(actor)[:120],
    }


def _priority(level) -> str:
    try:
        level = int(level or 0)
    except (TypeError, ValueError):
        level = 0
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def build_incident_cases(alerts: list[dict]) -> list[dict]:
    """Attach analyst workflow state to real Wazuh alert documents."""
    event_ids = [str(item.get("event_id") or "") for item in alerts]
    states = get_incident_states(event_ids)
    cases = []
    for alert in alerts:
        event_id = str(alert.get("event_id") or "")
        state = states.get(event_id) or {}
        cases.append(
            {
                **alert,
                "case_id": event_id,
                "priority": _priority(alert.get("level")),
                "status": state.get("status", "new"),
                "assignee": state.get("assignee", ""),
                "notes": state.get("notes", ""),
                "workflow_updated_at": state.get("updated_at", ""),
                "workflow_updated_by": state.get("updated_by", ""),
            }
        )
    return cases


def correlate_alerts(alerts: list[dict], window_minutes: int = 60) -> list[dict]:
    """Group related *real* FAST alerts into read-only correlation findings.

    Correlation is intentionally conservative: at least two Wazuh alert
    documents must share an asset/source pair inside the same time bucket.
    No synthetic alert is created and no Wazuh state is modified.
    """
    window_minutes = max(15, min(360, int(window_minutes)))
    buckets: dict[tuple[str, str, str], list[dict]] = defaultdict(list)

    for alert in alerts:
        timestamp = str(alert.get("timestamp") or "")
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            dt = dt.astimezone(timezone.utc)
        except (TypeError, ValueError):
            continue
        minute_bucket = (dt.hour * 60 + dt.minute) // window_minutes
        date_bucket = dt.strftime("%Y%m%d")
        bucket_id = f"{date_bucket}-{minute_bucket}"
        asset = str(alert.get("agent_id") or alert.get("agent_name") or "unknown")
        source = str(alert.get("source_ip") or "local")
        buckets[(asset, source, bucket_id)].append(alert)

    findings = []
    for (asset, source, _bucket_id), events in buckets.items():
        if len(events) < 2:
            continue
        events = sorted(events, key=lambda item: str(item.get("timestamp") or ""))
        rule_ids = sorted({str(item.get("rule_id") or "") for item in events if item.get("rule_id")})
        levels = []
        for item in events:
            try:
                levels.append(int(item.get("level") or 0))
            except (TypeError, ValueError):
                pass
        max_level = max(levels or [0])
        score = min(100, max_level * 5 + min(25, len(events) * 3) + min(20, len(rule_ids) * 7))
        event_ids = sorted(str(item.get("event_id") or "") for item in events)
        correlation_id = hashlib.sha256("|".join(event_ids).encode("utf-8")).hexdigest()[:12]
        title = (
            "Multi-stage FAST activity"
            if len(rule_ids) > 1
            else f"Repeated {events[-1].get('attack_type') or 'FAST detection'}"
        )
        findings.append(
            {
                "correlation_id": correlation_id,
                "title": title,
                "agent_id": asset,
                "agent_name": events[-1].get("agent_name") or asset,
                "source_ip": "" if source == "local" else source,
                "first_seen": events[0].get("timestamp") or "",
                "last_seen": events[-1].get("timestamp") or "",
                "event_count": len(events),
                "rule_ids": rule_ids,
                "max_level": max_level,
                "risk_score": score,
                "event_ids": event_ids,
            }
        )

    return sorted(findings, key=lambda item: (item["risk_score"], item["last_seen"]), reverse=True)


def calculate_asset_risk(agents: list[dict], alerts: list[dict]) -> list[dict]:
    """Return transparent risk scores from agent health + real FAST alerts."""
    by_agent: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        agent_id = str(alert.get("agent_id") or "")
        if agent_id:
            by_agent[agent_id].append(alert)

    results = []
    for agent in agents:
        agent_id = str(agent.get("id") or "")
        agent_alerts = by_agent.get(agent_id, [])
        levels = []
        for alert in agent_alerts:
            try:
                levels.append(int(alert.get("level") or 0))
            except (TypeError, ValueError):
                pass
        max_level = max(levels or [0])
        unique_rules = {str(item.get("rule_id") or "") for item in agent_alerts if item.get("rule_id")}
        status = str(agent.get("status") or "unknown").lower()
        score = 0
        reasons = []
        if status != "active":
            score += 25
            reasons.append(f"Agent status is {status}")
        if max_level >= 12:
            score += 35
            reasons.append("Critical FAST detection observed")
        elif max_level >= 10:
            score += 25
            reasons.append("High-severity FAST detection observed")
        elif max_level >= 7:
            score += 15
            reasons.append("Medium-severity FAST detection observed")
        if agent_alerts:
            volume = min(25, len(agent_alerts) * 3)
            score += volume
            reasons.append(f"{len(agent_alerts)} FAST alert(s) in the scoring window")
        if len(unique_rules) > 1:
            diversity = min(15, (len(unique_rules) - 1) * 7)
            score += diversity
            reasons.append(f"{len(unique_rules)} distinct FAST detections")
        score = min(100, score)
        if score >= 75:
            band = "critical"
        elif score >= 50:
            band = "high"
        elif score >= 25:
            band = "medium"
        else:
            band = "low"
        results.append(
            {
                **agent,
                "risk_score": score,
                "risk_band": band,
                "risk_reasons": reasons or ["No recent FAST detections and agent is active"],
                "alert_count": len(agent_alerts),
                "distinct_rules": len(unique_rules),
                "max_alert_level": max_level,
            }
        )
    return sorted(results, key=lambda item: (item["risk_score"], item.get("hostname", "")), reverse=True)
