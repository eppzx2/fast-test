from pathlib import Path


SETUP = Path("tests/acceptance/sim/setup_prereqs.sh")


def test_audit_setup_is_idempotent():
    text = SETUP.read_text(encoding="utf-8")
    assert "auditd execve rule already active" in text
    assert "augenrules --load 2>/dev/null || auditctl -R" not in text
    assert "auditctl -l 2>/dev/null | grep -q 'audit-wazuh-c'" in text


def test_audit_collection_still_configured_after_rule_setup():
    text = SETUP.read_text(encoding="utf-8")
    assert "ensure_audit_collection" in text
    assert "restart_agent_if_needed" in text
