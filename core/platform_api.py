"""FAST platform API endpoints layered on top of the existing IOC dashboard."""

from __future__ import annotations

from flask import jsonify, request

from core.wazuh_client import FAST_RULE_IDS, WazuhClient, WazuhIntegrationError


def get_wazuh_client() -> WazuhClient:
    return WazuhClient()


def inject_platform_ui(html: str) -> str:
    """Attach the additive platform UI without rewriting the legacy template."""
    css = '<link rel="stylesheet" href="/static/fast-platform.css">'
    js = '<script src="/static/fast-platform.js"></script>'
    if css not in html:
        html = html.replace("</head>", f"  {css}\n</head>")
    if js not in html:
        html = html.replace("</body>", f"  {js}\n</body>")
    return html


def register_platform_routes(app) -> None:
    @app.get("/api/wazuh/assets")
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
    def wazuh_alerts():
        try:
            limit = min(100, max(1, int(request.args.get("limit", 30))))
            minutes = min(1440, max(1, int(request.args.get("minutes", 30))))
        except (TypeError, ValueError):
            limit, minutes = 30, 30

        requested_rules = [
            value.strip()
            for value in request.args.get("rules", "").split(",")
            if value.strip()
        ]
        # The demo view is deliberately scoped to FAST-owned detection rules.
        allowed = set(FAST_RULE_IDS)
        rule_ids = [rule for rule in requested_rules if rule in allowed] or list(
            FAST_RULE_IDS
        )

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
