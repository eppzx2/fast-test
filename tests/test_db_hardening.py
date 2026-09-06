"""Regression tests for FAST IOC merge semantics."""

import pytest

from core import db


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "merge.db"))
    db.init_database()


def _ioc(feed, first_seen, last_seen, tags):
    return {
        "ioc_value": "1.2.3.4",
        "ioc_type": "ip",
        "source_feed": feed,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "tags": tags,
    }


def test_dedup_keeps_earliest_first_and_latest_last_and_merges_tags(temp_db):
    assert db.insert_ioc(
        _ioc(
            "feodo",
            "2026-09-05T10:00:00+00:00",
            "2026-09-05T11:00:00+00:00",
            ["botnet", "shared"],
        )
    )
    assert db.insert_ioc(
        _ioc(
            "spamhaus",
            "2026-09-01T08:00:00+00:00",
            "2026-09-06T12:00:00+00:00",
            ["drop", "shared"],
        )
    )

    stored = db.get_ioc("1.2.3.4", "ip")
    assert stored["first_seen"] == "2026-09-01T08:00:00+00:00"
    assert stored["last_seen"] == "2026-09-06T12:00:00+00:00"
    assert set(stored["source_feed"].split(",")) == {"feodo", "spamhaus"}
    assert stored["tags"] == ["botnet", "shared", "drop"]
    assert stored["confidence_score"] == 50


def test_update_ioc_recalculates_score(temp_db):
    db.insert_ioc(
        _ioc(
            "feodo",
            "2026-09-01T00:00:00+00:00",
            "2026-09-01T00:00:00+00:00",
            [],
        )
    )
    assert db.update_ioc(
        "1.2.3.4",
        "ip",
        "2026-09-02T00:00:00+00:00",
        "feodo,spamhaus,urlhaus",
    )
    assert db.get_ioc("1.2.3.4", "ip")["confidence_score"] == 75
