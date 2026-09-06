"""SQLite persistence for normalized FAST indicators of compromise."""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core import scoring

logger = logging.getLogger(__name__)
DB_PATH = "ioc_database.db"


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database() -> None:
    with _get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source_feed TEXT NOT NULL,
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL,
                confidence_score INTEGER DEFAULT 0,
                tags TEXT DEFAULT '[]',
                UNIQUE(ioc_value, ioc_type)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ioc_value_type ON ioc(ioc_value, ioc_type)"
        )
    logger.info("Database ready: %s", DB_PATH)


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _earliest(first: str, second: str) -> str:
    try:
        return first if _parse_timestamp(first) <= _parse_timestamp(second) else second
    except (TypeError, ValueError):
        return min(str(first), str(second))


def _latest(first: str, second: str) -> str:
    try:
        return first if _parse_timestamp(first) >= _parse_timestamp(second) else second
    except (TypeError, ValueError):
        return max(str(first), str(second))


def _normalize_tags(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, list) else [decoded]
        except json.JSONDecodeError:
            return [value]
    return [value]


def _merge_tags(existing: Any, incoming: Any) -> List[Any]:
    merged: List[Any] = []
    for tag in _normalize_tags(existing) + _normalize_tags(incoming):
        if tag not in merged:
            merged.append(tag)
    return merged


def _upsert_ioc_with_cursor(cursor: sqlite3.Cursor, ioc: Dict[str, Any]) -> bool:
    required = {"ioc_value", "ioc_type", "source_feed", "first_seen", "last_seen"}
    if not required.issubset(ioc):
        logger.error("IOC is missing required fields: %s", sorted(required - set(ioc)))
        return False

    value = str(ioc["ioc_value"]).strip()
    ioc_type = str(ioc["ioc_type"]).strip()
    source_feed = str(ioc["source_feed"]).strip()
    if not value or not ioc_type or not source_feed:
        logger.error("IOC has an empty value/type/source_feed")
        return False

    existing = cursor.execute(
        "SELECT id, source_feed, first_seen, last_seen, tags FROM ioc "
        "WHERE ioc_value = ? AND ioc_type = ?",
        (value, ioc_type),
    ).fetchone()

    if existing:
        feeds = {feed.strip() for feed in existing["source_feed"].split(",") if feed.strip()}
        feeds.update(feed.strip() for feed in source_feed.split(",") if feed.strip())
        merged_feeds = ",".join(sorted(feeds))
        merged_tags = _merge_tags(existing["tags"], ioc.get("tags", []))
        first_seen = _earliest(existing["first_seen"], str(ioc["first_seen"]))
        last_seen = _latest(existing["last_seen"], str(ioc["last_seen"]))
        score = scoring.calculate_score({"source_feed": merged_feeds})
        cursor.execute(
            """
            UPDATE ioc
               SET source_feed = ?, first_seen = ?, last_seen = ?,
                   confidence_score = ?, tags = ?
             WHERE id = ?
            """,
            (
                merged_feeds,
                first_seen,
                last_seen,
                score,
                json.dumps(merged_tags, ensure_ascii=False),
                existing["id"],
            ),
        )
    else:
        score = scoring.calculate_score({"source_feed": source_feed})
        cursor.execute(
            """
            INSERT INTO ioc
                (ioc_value, ioc_type, source_feed, first_seen, last_seen,
                 confidence_score, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                value,
                ioc_type,
                source_feed,
                str(ioc["first_seen"]),
                str(ioc["last_seen"]),
                score,
                json.dumps(_normalize_tags(ioc.get("tags", [])), ensure_ascii=False),
            ),
        )
    return True


def insert_ioc(ioc: Dict[str, Any]) -> bool:
    try:
        with _get_connection() as conn:
            return _upsert_ioc_with_cursor(conn.cursor(), ioc)
    except (sqlite3.Error, TypeError, ValueError) as exc:
        logger.error("IOC insert error: %s", exc)
        return False


def insert_batch(iocs: List[Dict[str, Any]]) -> int:
    if not iocs:
        return 0
    success = 0
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            for ioc in iocs:
                try:
                    if _upsert_ioc_with_cursor(cursor, ioc):
                        success += 1
                except (sqlite3.Error, TypeError, ValueError, KeyError) as exc:
                    logger.error("IOC skipped in batch insert: %s", exc)
        logger.info("Batch insert: %d/%d IOCs processed", success, len(iocs))
        return success
    except sqlite3.Error as exc:
        logger.error("Batch insert connection error: %s", exc)
        return success


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    result = dict(row)
    result["tags"] = _normalize_tags(result.get("tags"))
    return result


def get_ioc(ioc_value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
    try:
        with _get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM ioc WHERE ioc_value = ? AND ioc_type = ?",
                (ioc_value, ioc_type),
            ).fetchone()
        return _row_to_dict(row) if row else None
    except sqlite3.Error as exc:
        logger.error("IOC query error: %s", exc)
        return None


def get_all_iocs() -> List[Dict[str, Any]]:
    try:
        with _get_connection() as conn:
            rows = conn.execute("SELECT * FROM ioc ORDER BY last_seen DESC").fetchall()
        return [_row_to_dict(row) for row in rows]
    except sqlite3.Error as exc:
        logger.error("Error querying all IOCs: %s", exc)
        return []


def update_ioc(ioc_value: str, ioc_type: str, last_seen: str, source_feed: str) -> bool:
    """Directly replace last_seen/source_feed and keep confidence score consistent."""
    try:
        score = scoring.calculate_score({"source_feed": source_feed})
        with _get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE ioc
                   SET last_seen = ?, source_feed = ?, confidence_score = ?
                 WHERE ioc_value = ? AND ioc_type = ?
                """,
                (last_seen, source_feed, score, ioc_value, ioc_type),
            )
            return cursor.rowcount > 0
    except sqlite3.Error as exc:
        logger.error("IOC update error: %s", exc)
        return False


def delete_ioc(ioc_value: str, ioc_type: str) -> bool:
    try:
        with _get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM ioc WHERE ioc_value = ? AND ioc_type = ?",
                (ioc_value, ioc_type),
            )
            return cursor.rowcount > 0
    except sqlite3.Error as exc:
        logger.error("IOC delete error: %s", exc)
        return False


def get_count() -> int:
    try:
        with _get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM ioc").fetchone()
        return int(row["cnt"]) if row else 0
    except sqlite3.Error as exc:
        logger.error("IOC count query error: %s", exc)
        return 0


def close_database() -> None:
    """Compatibility no-op; connections are scoped per operation."""
    return None
