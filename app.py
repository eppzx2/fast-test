"""Lightweight Flask dashboard for the FAST security platform."""

import logging
import os

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_file

from core import db, exporter, fetchers, normalizer
from core.auth import current_actor, require_role, setup_auth
from core.detections import DETECTIONS
from core.platform_api import inject_platform_ui, register_platform_routes
from core.security_ops import audit_event

load_dotenv()

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

setup_auth(app)

_configured_db_path = os.getenv("FAST_DB_PATH", "").strip()
if _configured_db_path:
    db.DB_PATH = _configured_db_path

register_platform_routes(app)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _request_hostname() -> str:
    """Return the browser-facing hostname without a port."""
    host = (request.host or "").strip()
    if host.startswith("[") and "]" in host:
        return host[1 : host.index("]")].lower()
    return host.split(":", 1)[0].lower()


def _ui_runtime_config() -> dict:
    """Build non-secret UI routing metadata from env + request hostname."""
    hostname = _request_hostname()
    configured_wazuh = os.getenv("FAST_WAZUH_DASHBOARD_URL", "").strip()
    configured_public = os.getenv("FAST_PUBLIC_URL", "").strip()
    configured_mode = os.getenv("FAST_DEPLOYMENT_MODE", "local").strip() or "local"
    local_wazuh_port = os.getenv("FAST_WAZUH_DASHBOARD_LOCAL_PORT", "5601").strip() or "5601"

    if configured_wazuh:
        wazuh_url = configured_wazuh
        wazuh_access = "configured"
    elif hostname.endswith(".ts.net"):
        wazuh_url = f"https://{hostname}:8443"
        wazuh_access = "tailnet"
    else:
        wazuh_url = f"https://localhost:{local_wazuh_port}"
        wazuh_access = "local"

    if configured_public:
        public_url = configured_public
        deployment_mode = configured_mode
    elif hostname.endswith(".ts.net"):
        public_url = f"https://{hostname}"
        deployment_mode = "tailscale-funnel"
    else:
        public_url = ""
        deployment_mode = configured_mode

    return {
        "product_name": "FAST",
        "product_subtitle": "Fully Automated SIEM & Threat Intelligence Platform",
        "wazuh_dashboard_url": wazuh_url,
        "wazuh_access": wazuh_access,
        "public_url": public_url,
        "deployment_mode": deployment_mode,
    }


def _audit_nonfatal(action: str, *, object_type: str = "", object_id: str = "", details=None) -> None:
    try:
        actor, role = current_actor()
        audit_event(
            action,
            actor=actor,
            role=role,
            object_type=object_type,
            object_id=object_id,
            details=details or {},
        )
    except Exception:
        logger.exception("Could not write FAST audit event: %s", action)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


@app.route("/")
def index():
    db.init_database()
    return inject_platform_ui(render_template("index.html"))


@app.route("/api/health")
def health():
    """Cheap liveness endpoint used by Docker health checks and the FAST UI."""
    try:
        db.init_database()
        return jsonify(
            {
                "status": "ok",
                "service": "fast-ioc-collector-web",
                "ioc_count": db.get_count(),
            }
        )
    except Exception as exc:
        logger.error("/api/health error: %s", exc)
        return jsonify({"status": "error"}), 503


@app.route("/api/ui-config")
def ui_config():
    """Return non-secret UI configuration only."""
    return jsonify(_ui_runtime_config())


@app.route("/api/detections")
def detections():
    """Expose the stable FAST detection catalogue for backward compatibility."""
    return jsonify({"items": DETECTIONS, "total": len(DETECTIONS)})


@app.route("/api/iocs")
def get_iocs():
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
        min_score = max(0, min(100, int(request.args.get("min_score", 0))))
    except (TypeError, ValueError):
        page, per_page, min_score = 1, 50, 0

    type_filter = request.args.get("type", "").strip()
    feed_filter = request.args.get("feed", "").strip()
    search = request.args.get("search", "").strip().lower()
    all_iocs = db.get_all_iocs()

    if type_filter:
        all_iocs = [item for item in all_iocs if item.get("ioc_type") == type_filter]
    if feed_filter:
        all_iocs = [item for item in all_iocs if feed_filter in (item.get("source_feed") or "")]
    if search:
        all_iocs = [item for item in all_iocs if search in str(item.get("ioc_value", "")).lower()]
    if min_score:
        all_iocs = [
            item
            for item in all_iocs
            if int(item.get("confidence_score", 0) or 0) >= min_score
        ]

    total = len(all_iocs)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    return jsonify(
        {
            "items": all_iocs[start : start + per_page],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
        }
    )


@app.route("/api/fetch", methods=["POST"])
@require_role("admin", csrf=True)
def fetch_feeds():
    try:
        db.init_database()
        raw_feeds = fetchers.fetch_all_feeds()
        raw_counts = {name: len(items) for name, items in raw_feeds.items()}
        if sum(raw_counts.values()) == 0:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "All configured threat feeds returned zero records",
                        "raw_counts": raw_counts,
                    }
                ),
                503,
            )

        normalized = normalizer.normalize_all(raw_feeds)
        if not normalized:
            return jsonify({"status": "error", "message": "No records normalized"}), 500
        processed = db.insert_batch(normalized)
        if processed == 0:
            return jsonify({"status": "error", "message": "No records stored"}), 500

        _audit_nonfatal(
            "intelligence.sync",
            object_type="threat_intelligence",
            details={"normalized_count": len(normalized), "processed_count": processed},
        )
        return jsonify(
            {
                "status": "ok",
                "raw_counts": raw_counts,
                "normalized_count": len(normalized),
                "processed_count": processed,
                "inserted_count": processed,
                "total_in_db": db.get_count(),
            }
        )
    except Exception as exc:
        logger.exception("/api/fetch error: %s", exc)
        return jsonify({"status": "error", "message": "Feed refresh failed"}), 500


@app.route("/api/export")
def export_iocs():
    fmt = request.args.get("format", "csv").lower()
    iocs = db.get_all_iocs()
    if not iocs:
        return jsonify({"status": "error", "message": "No IOCs found in the database"}), 400

    if fmt == "csv":
        ok = exporter.export_to_csv(iocs)
        filepath = os.path.join(exporter.EXPORT_DIR, "ioc_export.csv")
        mimetype = "text/csv"
    elif fmt == "json":
        ok = exporter.export_to_json(iocs)
        filepath = os.path.join(exporter.EXPORT_DIR, "ioc_export.json")
        mimetype = "application/json"
    else:
        return jsonify({"status": "error", "message": f"Unknown format: {fmt}"}), 400

    if not ok or not os.path.exists(filepath):
        return jsonify({"status": "error", "message": "Export failed"}), 500
    _audit_nonfatal(
        "intelligence.export",
        object_type="ioc_database",
        object_id=fmt,
        details={"record_count": len(iocs)},
    )
    return send_file(filepath, mimetype=mimetype, as_attachment=True)


@app.route("/api/stats")
def get_stats():
    iocs = db.get_all_iocs()
    by_type = {}
    by_score = {"25": 0, "50": 0, "75": 0, "100": 0}
    feed_counts = {"feodo": 0, "urlhaus": 0, "malwarebazaar": 0, "spamhaus": 0}

    for ioc in iocs:
        ioc_type = ioc.get("ioc_type", "unknown")
        by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
        score = int(ioc.get("confidence_score", 0) or 0)
        bucket = str(min(100, max(25, (score // 25) * 25))) if score else "25"
        if bucket in by_score:
            by_score[bucket] += 1
        for feed in (ioc.get("source_feed") or "").split(","):
            feed = feed.strip()
            if feed in feed_counts:
                feed_counts[feed] += 1

    return jsonify(
        {
            "total": len(iocs),
            "by_type": by_type,
            "by_feed": feed_counts,
            "by_score": by_score,
        }
    )


if __name__ == "__main__":
    host = os.getenv("FAST_WEB_HOST", "0.0.0.0")
    port = int(os.getenv("FAST_WEB_PORT", "5000"))
    app.run(debug=_env_bool("FAST_WEB_DEBUG", False), host=host, port=port)
