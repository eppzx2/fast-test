"""CLI exit-code regressions for automated deploy/refresh use."""

from unittest.mock import patch

import cli
from core import db


def test_run_fetch_fails_when_all_feeds_are_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "empty.db"))
    empty = {"feodo": [], "urlhaus": [], "malwarebazaar": [], "spamhaus": []}
    with patch("cli.fetchers.fetch_all_feeds", return_value=empty):
        assert cli.run_fetch() is False


def test_main_returns_nonzero_on_failed_fetch(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "main.db"))
    empty = {"feodo": [], "urlhaus": [], "malwarebazaar": [], "spamhaus": []}
    with patch("cli.fetchers.fetch_all_feeds", return_value=empty):
        assert cli.main(["--fetch"]) == 1


def test_wazuh_export_fails_when_db_has_no_valid_ipv4(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "hash-only.db"))
    db.init_database()
    assert db.insert_ioc(
        {
            "ioc_value": "a" * 64,
            "ioc_type": "hash",
            "source_feed": "malwarebazaar",
            "first_seen": "2026-09-06T00:00:00+00:00",
            "last_seen": "2026-09-06T00:00:00+00:00",
            "tags": [],
        }
    )
    assert cli.run_export("wazuh") is False
