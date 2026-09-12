"""Authentication/RBAC regression tests."""

import json

import app as webapp
from core import db, security_ops


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "auth-ioc.db"))
    monkeypatch.setattr(security_ops, "OPS_DB_PATH", str(tmp_path / "auth-ops.db"))
    webapp.app.config.update(TESTING=True)
    return webapp.app.test_client()


def test_auth_disabled_preserves_existing_access(tmp_path, monkeypatch):
    monkeypatch.setenv("FAST_AUTH_ENABLED", "0")
    client = _client(tmp_path, monkeypatch)
    assert client.get("/").status_code == 200
    payload = client.get("/api/auth/me").get_json()
    assert payload["enabled"] is False
    assert payload["role"] == "admin"


def test_auth_enabled_redirects_ui_and_accepts_login(tmp_path, monkeypatch):
    monkeypatch.setenv("FAST_AUTH_ENABLED", "1")
    monkeypatch.setenv("FAST_ADMIN_USER", "admin")
    monkeypatch.setenv("FAST_ADMIN_PASSWORD", "test-password")
    client = _client(tmp_path, monkeypatch)

    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

    login = client.post("/login", data={"username": "admin", "password": "test-password", "next": "/"})
    assert login.status_code == 302
    me = client.get("/api/auth/me").get_json()
    assert me["enabled"] is True
    assert me["role"] == "admin"
    assert me["csrf_token"]


def test_viewer_cannot_run_admin_action(tmp_path, monkeypatch):
    monkeypatch.setenv("FAST_AUTH_ENABLED", "1")
    monkeypatch.setenv(
        "FAST_USERS_JSON",
        json.dumps({"viewer": {"password": "viewer-pass", "role": "viewer"}}),
    )
    monkeypatch.delenv("FAST_ADMIN_PASSWORD", raising=False)
    client = _client(tmp_path, monkeypatch)
    client.post("/login", data={"username": "viewer", "password": "viewer-pass", "next": "/"})
    csrf = client.get("/api/auth/me").get_json()["csrf_token"]
    response = client.post("/api/fetch", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 403
