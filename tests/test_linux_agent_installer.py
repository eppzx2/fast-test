from pathlib import Path


INSTALLER = Path("linux/install-wazuh-agent.sh")


def test_linux_agent_installer_uses_wazuh_native_config_validator():
    text = INSTALLER.read_text(encoding="utf-8")
    assert "/var/ossec/bin/wazuh-agentd -t" in text
    assert "xmllint --noout" not in text


def test_linux_agent_installer_keeps_service_start_checks():
    text = INSTALLER.read_text(encoding="utf-8")
    assert "systemctl restart wazuh-agent" in text
    assert "systemctl is-active --quiet wazuh-agent" in text
