"""Lightweight Flask dashboard for the FAST IOC collector."""

import logging
import os

from flask import Flask, jsonify, render_template, request, send_file

from core import db, exporter, fetchers, normalizer

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
    return render_template("index.html")


@app.route("/api/health")
def health():
    """Cheap liveness endpoint used by Docker health checks."""
    try:
        db.init_database()
        return jsonify({"status": "ok", "ioc_count": db.get_count()})
    except Exception as exc:
        logger.error("/api/health error: %s", exc)
        return jsonify({"status": "error"}), 503


@app.route("/api/iocs")
def get_iocs():
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except (TypeError, ValueError):
        page, per_page = 1, 50

    type_filter = request.args.get("type", "").strip()
    feed_filter = request.args.get("feed", "").strip()
    search = request.args.get("search", "").strip().lower()
    all_iocs = db.get_all_iocs()

    if type_filter:
        all_iocs = [item for item in all_iocs if item.get("ioc_type") == type_filter]
    if feed_filter:
        all_iocs = [
            item for item in all_iocs if feed_filter in (item.get("source_feed") or "")
        ]
    if search:
        all_iocs = [
            item
            for item in all_iocs
            if search in str(item.get("ioc_value", "")).lower()
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

        return jsonify(
            {
                "status": "ok",
                "raw_counts": raw_counts,
                "normalized_count": len(normalized),
                "processed_count": processed,
                # Backward-compatible field name used by the existing UI.
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
        return jsonify({"status": "error", "message": "Bazada IOC yoxdur"}), 400

    if fmt == "csv":
        ok = exporter.export_to_csv(iocs)
        filepath = os.path.join(exporter.EXPORT_DIR, "ioc_export.csv")
        mimetype = "text/csv"
    elif fmt == "json":
        ok = exporter.export_to_json(iocs)
        filepath = os.path.join(exporter.EXPORT_DIR, "ioc_export.json")
        mimetype = "application/json"
    else:
        return jsonify({"status": "error", "message": f"Naməlum format: {fmt}"}), 400

    if not ok or not os.path.exists(filepath):
        return jsonify({"status": "error", "message": "Export uğursuz oldu"}), 500
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
    # Debug mode is NEVER on implicitly in deployed environments.
    app.run(debug=_env_bool("FAST_WEB_DEBUG", False), host=host, port=port)
