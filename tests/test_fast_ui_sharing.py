"""Regression tests for the final FAST UI + Tailscale access model."""

from pathlib import Path

import app as webapp
from core import db


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "sharing-test.db"))
    webapp.app.config.update(TESTING=True)
    return webapp.app.test_client()


def test_tsnet_request_derives_tailnet_wazuh_url(tmp_path, monkeypatch):
    monkeypatch.delenv("FAST_WAZUH_DASHBOARD_URL", raising=False)
    monkeypatch.delenv("FAST_PUBLIC_URL", raising=False)
    monkeypatch.setenv("FAST_DEPLOYMENT_MODE", "local")
    client = _client(tmp_path, monkeypatch)

    response = client.get(
        "/api/ui-config",
        headers={"Host": "kali.example-tailnet.ts.net"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["public_url"] == "https://kali.example-tailnet.ts.net"
    assert payload["deployment_mode"] == "tailscale-funnel"
    assert payload["wazuh_dashboard_url"] == "https://kali.example-tailnet.ts.net:8443"
    assert payload["wazuh_access"] == "tailnet"


def test_local_request_derives_local_wazuh_url(tmp_path, monkeypatch):
    monkeypatch.delenv("FAST_WAZUH_DASHBOARD_URL", raising=False)
    monkeypatch.delenv("FAST_PUBLIC_URL", raising=False)
    monkeypatch.setenv("FAST_WAZUH_DASHBOARD_LOCAL_PORT", "5601")
    client = _client(tmp_path, monkeypatch)

    response = client.get("/api/ui-config", headers={"Host": "localhost:5000"})
    payload = response.get_json()

    assert payload["wazuh_dashboard_url"] == "https://localhost:5601"
    assert payload["wazuh_access"] == "local"


def test_wazuh_dashboard_no_longer_claims_host_port_443():
    override = Path("docker/healthcheck.override.yml").read_text()
    assert "ports: !override" in override
    assert '127.0.0.1:${FAST_WAZUH_DASHBOARD_LOCAL_PORT:-5601}:5601' in override
    assert '"443:5601"' not in override


def test_share_helper_separates_public_ui_from_private_wazuh():
    script = Path("bin/fast-share").read_text()
    assert "funnel --bg --yes --https=443" in script
    assert "http://127.0.0.1:${UI_PORT}" in script
    assert "serve --bg --yes --https=8443" in script
    assert "https+insecure://127.0.0.1:${WAZUH_PORT}" in script


def test_obsolete_preview_deployer_is_removed():
    assert not Path("deploy-fast-ui.sh").exists()
    assert not Path("docker/fast-ui.Dockerfile").exists()
