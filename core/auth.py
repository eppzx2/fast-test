"""Optional session authentication and role-based access control for FAST.

Authentication is disabled by default so existing local/demo deployments keep
working exactly as before. When FAST_AUTH_ENABLED=1, every UI/API request except
health/static/login requires a session. State-changing API routes can also
require a CSRF token and a minimum role.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

ROLE_RANK = {"viewer": 10, "analyst": 20, "admin": 30}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def auth_enabled() -> bool:
    return _env_bool("FAST_AUTH_ENABLED", False)


def _normalise_role(value: str) -> str:
    value = str(value or "viewer").strip().lower()
    return value if value in ROLE_RANK else "viewer"


def _configured_users() -> dict[str, dict]:
    users: dict[str, dict] = {}
    raw = os.getenv("FAST_USERS_JSON", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            for username, value in parsed.items():
                if not isinstance(value, dict):
                    continue
                password = str(value.get("password") or "")
                if username and password:
                    users[str(username)] = {
                        "password": password,
                        "role": _normalise_role(value.get("role", "viewer")),
                    }

    admin_password = os.getenv("FAST_ADMIN_PASSWORD", "")
    if admin_password:
        admin_user = os.getenv("FAST_ADMIN_USER", "admin").strip() or "admin"
        users.setdefault(
            admin_user,
            {"password": admin_password, "role": "admin"},
        )
    return users


def _verify_password(stored: str, supplied: str) -> bool:
    stored = str(stored or "")
    supplied = str(supplied or "")
    if stored.startswith(("pbkdf2:", "scrypt:")):
        try:
            return check_password_hash(stored, supplied)
        except ValueError:
            return False
    return hmac.compare_digest(stored, supplied)


def current_identity() -> dict | None:
    if not auth_enabled():
        return {
            "username": "local",
            "role": "admin",
            "auth_enabled": False,
        }
    username = session.get("fast_username")
    role = _normalise_role(session.get("fast_role", "viewer"))
    if not username:
        return None
    return {"username": username, "role": role, "auth_enabled": True}


def current_actor() -> tuple[str, str]:
    identity = current_identity() or {}
    return str(identity.get("username") or "anonymous"), str(identity.get("role") or "unknown")


def csrf_token() -> str:
    if "fast_csrf" not in session:
        session["fast_csrf"] = secrets.token_urlsafe(32)
    return str(session["fast_csrf"])


def _csrf_valid() -> bool:
    expected = str(session.get("fast_csrf") or "")
    provided = request.headers.get("X-CSRF-Token", "")
    return bool(expected and provided and hmac.compare_digest(expected, provided))


def require_role(minimum_role: str = "viewer", *, csrf: bool = False):
    minimum_role = _normalise_role(minimum_role)

    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if not auth_enabled():
                return func(*args, **kwargs)
            identity = current_identity()
            if not identity:
                return jsonify({"status": "error", "message": "Authentication required"}), 401
            if ROLE_RANK.get(identity["role"], 0) < ROLE_RANK[minimum_role]:
                return jsonify({"status": "error", "message": "Insufficient role"}), 403
            if csrf and request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _csrf_valid():
                return jsonify({"status": "error", "message": "CSRF validation failed"}), 403
            g.fast_user = identity
            return func(*args, **kwargs)

        return wrapped

    return decorator


def _safe_next(value: str | None) -> str:
    value = str(value or "").strip()
    if not value:
        return url_for("index")
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc or not value.startswith("/") or value.startswith("//"):
        return url_for("index")
    return value


def setup_auth(app) -> None:
    configured_secret = os.getenv("FAST_SESSION_SECRET", "").strip()
    app.secret_key = configured_secret or secrets.token_hex(32)
    try:
        session_hours = max(1, min(24, int(os.getenv("FAST_SESSION_HOURS", "8"))))
    except (TypeError, ValueError):
        session_hours = 8
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=_env_bool("FAST_SESSION_COOKIE_SECURE", False),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=session_hours),
    )
    if auth_enabled() and not configured_secret:
        app.logger.warning(
            "FAST authentication is enabled without FAST_SESSION_SECRET; sessions will reset on restart."
        )

    @app.before_request
    def _fast_auth_gate():
        if not auth_enabled():
            g.fast_user = current_identity()
            return None

        endpoint = request.endpoint or ""
        path = request.path or ""
        if endpoint in {"static", "login", "health"} or path.startswith("/static/"):
            return None

        identity = current_identity()
        if identity:
            g.fast_user = identity
            return None

        if path.startswith("/api/"):
            return jsonify({"status": "error", "message": "Authentication required"}), 401
        return redirect(url_for("login", next=request.full_path.rstrip("?")))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not auth_enabled():
            return redirect(url_for("index"))
        users = _configured_users()
        error = ""
        status = 200
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = users.get(username)
            if user and _verify_password(user["password"], password):
                session.clear()
                session.permanent = True
                session["fast_username"] = username
                session["fast_role"] = user["role"]
                csrf_token()
                try:
                    from core.security_ops import audit_event

                    audit_event("login", actor=username, role=user["role"], object_type="session")
                except Exception:
                    app.logger.exception("Could not write FAST login audit event")
                return redirect(_safe_next(request.form.get("next") or request.args.get("next")))
            error = "Invalid username or password."
            status = 401
        if not users:
            error = "Authentication is enabled but no FAST users are configured."
            status = 503
        return (
            render_template(
                "login.html",
                error=error,
                next_path=_safe_next(request.args.get("next")),
            ),
            status,
        )

    @app.post("/logout")
    @require_role("viewer", csrf=True)
    def logout():
        actor, role = current_actor()
        try:
            from core.security_ops import audit_event

            audit_event("logout", actor=actor, role=role, object_type="session")
        except Exception:
            app.logger.exception("Could not write FAST logout audit event")
        session.clear()
        return jsonify({"status": "ok"})

    @app.get("/api/auth/me")
    def auth_me():
        identity = current_identity()
        if not identity:
            return jsonify({"status": "error", "message": "Authentication required"}), 401
        return jsonify(
            {
                "status": "ok",
                "enabled": auth_enabled(),
                "username": identity["username"],
                "role": identity["role"],
                "csrf_token": csrf_token() if auth_enabled() else "",
            }
        )
