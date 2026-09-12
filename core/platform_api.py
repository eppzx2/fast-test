"""FAST platform API endpoints layered on top of the existing IOC dashboard."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

from core.auth import current_actor, require_role
from core.detections import DETECTIONS
from core.security_ops import (
    audit_event,
    build_incident_cases,
    calculate_asset_risk,
    correlate_alerts,
    get_incident_states,
    list_audit_events,
    update_incident_state,
)
from core.wazuh_client import FAST_RULE_IDS, WazuhClient, WazuhIntegrationError


def get_wazuh_client() -> WazuhClient:
    return WazuhClient()


def inject_platform_ui(html: str) -> str:
    """Attach additive platform assets without rewriting the legacy template."""
    styles = [
        '<link rel="stylesheet" href="/static/fast-platform.css">',
        '<link rel="stylesheet" href="/static/security-ops.css">',
    ]
    scripts = [
        '<script src="/static/fast-platform.js"></script>',
        '<script src="/static/security-ops.js"></script>',
    ]
    for asset in styles:
        if asset not in html:
            html = html.replace("</head>", f"  {asset}\n</head>")
    for asset in scripts:
        if asset not in html:
            html = html.replace("</body>", f"  {asset}\n</body>")
    return html


def _parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _validation_payload(activity: list[dict], fresh_minutes: int) -> list[dict]:
    now = datetime.now(timezone.utc)
    by_rule = {str(item.get("rule_id")): item for item in activity}
    results = []
    for detection in DETECTIONS:
        metric = by_rule.get(detection["id"], {})
        last_triggered = metric.get("last_triggered") or ""
        last_dt = _parse_iso(last_triggered)
        if last_dt and last_dt >= now - timedelta(minutes=fresh_minutes):
            validation = "pass"
        elif last_dt:
            validation = "stale"
        else:
            validation = "waiting"
        results.append(
            {
                **detection,
                "validation": validation,
                "last_triggered": last_triggered,
                "last_agent": metric.get("last_agent") or "",
                "count_24h": int(metric.get("count") or 0),
            }
        )
    return results


def register_platform_routes(app) -> None:
    @app.get("/api/wazuh/assets")
    @require_role("viewer")
    def wazuh_assets():
        try:
            data = get_wazuh_client().list_agents()
            return jsonify({"status": "ok", **data})
        except WazuhIntegrationError as exc:
            app.logger.warning("Wazuh asset catalogue unavailable: %s", exc)
            return (
                jsonify(
                    {
                        "status": "unavailable",
                        "source": "wazuh-server-api",
                        "items": [],
                        "total": 0,
                        "message": str(exc),
                    }
                ),
                503,
            )

    @app.get("/api/wazuh/alerts")
    @require_role("viewer")
    def wazuh_alerts():
        try:
            limit = min(500, max(1, int(request.args.get("limit", 30))))
            minutes = min(10080, max(1, int(request.args.get("minutes", 30))))
        except (TypeError, ValueError):
            limit, minutes = 30, 30

        requested_rules = [
            value.strip()
            for value in request.args.get("rules", "").split(",")
            if value.strip()
        ]
        allowed = set(FAST_RULE_IDS)
        rule_ids = [rule for rule in requested_rules if rule in allowed] or list(FAST_RULE_IDS)

        try:
            data = get_wazuh_client().recent_alerts(
                rule_ids=rule_ids, limit=limit, minutes=minutes
            )
            return jsonify({"status": "ok", **data})
        except WazuhIntegrationError as exc:
            app.logger.warning("Wazuh live alerts unavailable: %s", exc)
            return (
                jsonify(
                    {
                        "status": "unavailable",
                        "source": "wazuh-indexer",
                        "items": [],
                        "total": 0,
                        "window_minutes": minutes,
                        "rule_ids": rule_ids,
                        "message": str(exc),
                    }
                ),
                503,
            )

    @app.get("/api/security/assets")
    @require_role("viewer")
    def security_assets():
        """Asset catalogue enriched with transparent FAST risk scoring."""
        try:
            client = get_wazuh_client()
            agents = client.list_agents()
            alerts = client.recent_alerts(rule_ids=FAST_RULE_IDS, limit=500, minutes=1440)
            items = calculate_asset_risk(agents.get("items", []), alerts.get("items", []))
            return jsonify(
                {
                    "status": "ok",
                    "source": "wazuh-server-api+wazuh-indexer",
                    "items": items,
                    "total": len(items),
                    "alert_sampled": bool(alerts.get("sampled")),
                    "risk_scope": "Wazuh agent health + real FAST detections from the last 24 hours",
                }
            )
        except WazuhIntegrationError as exc:
            app.logger.warning("FAST asset risk unavailable: %s", exc)
            return jsonify({"status": "unavailable", "items": [], "total": 0, "message": str(exc)}), 503

    @app.get("/api/security/detections")
    @require_role("viewer")
    def security_detections():
        """Detection-engineering view using live Wazuh activity, not fake counters."""
        try:
            client = get_wazuh_client()
            activity = client.rule_activity(rule_ids=FAST_RULE_IDS, minutes=1440)
            agents = client.list_agents().get("items", [])
            active_agents = sum(1 for item in agents if str(item.get("status")).lower() == "active")
            total_agents = len(agents)
            by_rule = {str(item.get("rule_id")): item for item in activity.get("items", [])}
            items = []
            for detection in DETECTIONS:
                metric = by_rule.get(detection["id"], {})
                items.append(
                    {
                        **detection,
                        "alerts_24h": int(metric.get("count") or 0),
                        "last_triggered": metric.get("last_triggered") or "",
                        "last_agent": metric.get("last_agent") or "",
                        "active_agents": active_agents,
                        "total_agents": total_agents,
                    }
                )
            return jsonify(
                {
                    "status": "ok",
                    "source": "wazuh-indexer+wazuh-server-api",
                    "items": items,
                    "total": len(items),
                    "coverage_scope": "Connected Wazuh agent fleet; not proof that every rule applies to every OS",
                }
            )
        except WazuhIntegrationError as exc:
            app.logger.warning("Detection health unavailable: %s", exc)
            return jsonify({"status": "unavailable", "items": [], "total": 0, "message": str(exc)}), 503

    @app.get("/api/security/validation")
    @require_role("viewer")
    def security_validation():
        try:
            fresh_minutes = max(5, min(240, int(os.getenv("FAST_VALIDATION_FRESH_MINUTES", "30"))))
        except (TypeError, ValueError):
            fresh_minutes = 30
        try:
            activity = get_wazuh_client().rule_activity(rule_ids=FAST_RULE_IDS, minutes=1440)
            items = _validation_payload(activity.get("items", []), fresh_minutes)
            return jsonify(
                {
                    "status": "ok",
                    "source": "wazuh-indexer",
                    "items": items,
                    "fresh_minutes": fresh_minutes,
                    "message": "PASS means the expected real Wazuh rule fired inside the freshness window.",
                }
            )
        except WazuhIntegrationError as exc:
            app.logger.warning("Detection validation unavailable: %s", exc)
            return jsonify({"status": "unavailable", "items": [], "message": str(exc)}), 503

    @app.get("/api/security/incidents")
    @require_role("viewer")
    def security_incidents():
        try:
            minutes = min(10080, max(30, int(request.args.get("minutes", 1440))))
            limit = min(500, max(1, int(request.args.get("limit", 300))))
        except (TypeError, ValueError):
            minutes, limit = 1440, 300
        try:
            alerts = get_wazuh_client().recent_alerts(
                rule_ids=FAST_RULE_IDS, limit=limit, minutes=minutes
            )
            cases = build_incident_cases(alerts.get("items", []))
            correlations = correlate_alerts(alerts.get("items", []), window_minutes=60)
            return jsonify(
                {
                    "status": "ok",
                    "source": "wazuh-indexer+fast-analyst-state",
                    "items": cases,
                    "total": alerts.get("total", len(cases)),
                    "sampled": bool(alerts.get("sampled")),
                    "correlations": correlations,
                    "correlation_note": "Correlation groups only real FAST alert documents; it does not synthesize Wazuh alerts.",
                }
            )
        except WazuhIntegrationError as exc:
            app.logger.warning("Incident workflow unavailable: %s", exc)
            return jsonify({"status": "unavailable", "items": [], "correlations": [], "message": str(exc)}), 503

    @app.patch("/api/security/incidents/<event_id>")
    @require_role("analyst", csrf=True)
    def update_incident(event_id: str):
        payload = request.get_json(silent=True) or {}
        try:
            client = get_wazuh_client()
            recent = client.recent_alerts(rule_ids=FAST_RULE_IDS, limit=500, minutes=10080)
            matching = next((item for item in recent.get("items", []) if str(item.get("event_id")) == event_id), None)
            existing = get_incident_states([event_id]).get(event_id, {})
            if not matching and not existing:
                return jsonify({"status": "error", "message": "Real Wazuh alert not found in the searchable window"}), 404
            actor, role = current_actor()
            state = update_incident_state(
                event_id,
                status=payload.get("status", existing.get("status", "new")),
                assignee=payload.get("assignee", existing.get("assignee", "")),
                notes=payload.get("notes", existing.get("notes", "")),
                actor=actor,
            )
            audit_event(
                "incident.update",
                actor=actor,
                role=role,
                object_type="wazuh_alert",
                object_id=event_id,
                details={"status": state["status"], "assignee": state["assignee"]},
            )
            return jsonify({"status": "ok", "item": state})
        except ValueError as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400
        except WazuhIntegrationError as exc:
            return jsonify({"status": "unavailable", "message": str(exc)}), 503

    @app.get("/api/security/audit")
    @require_role("admin")
    def security_audit():
        try:
            limit = min(500, max(1, int(request.args.get("limit", 100))))
        except (TypeError, ValueError):
            limit = 100
        items = list_audit_events(limit)
        return jsonify({"status": "ok", "items": items, "total": len(items)})
