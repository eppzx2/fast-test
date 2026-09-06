"""
Acceptance test: wget masquerading as httpd (LOLBin) -> Wazuh rules
80792 -> 100220 -> 100221.

The target must first run tests/acceptance/sim/setup_prereqs.sh. That ensures
auditd watches execve and the Wazuh agent collects /var/log/audit/audit.log.
The simulation must execute on the target because auditd only sees local execs.
"""

import os
import subprocess
from pathlib import Path

import pytest

AUDIT_EXEC_RULE_ID = 80792
MASQUERADE_RULE_ID = 100220
RULE_ID = 100221
SIM_SCRIPT = Path(__file__).parent / "sim" / "simulate_lolbin.sh"


def test_wget_masquerading_as_httpd_triggers_rule_100221(alert_line_count, wait_for_rule_alert):
    target_host = os.environ.get("TARGET_HOST")
    if not target_host:
        pytest.skip(
            "TARGET_HOST env var not set - point it at a Linux target with a "
            "Wazuh agent, auditd, and SSH key-based access"
        )

    ssh_user = os.environ.get("TARGET_SSH_USER", "root")
    since_line = alert_line_count()
    script_content = SIM_SCRIPT.read_text()

    result = subprocess.run(
        [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
            f"{ssh_user}@{target_host}", "bash -s",
        ],
        input=script_content,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"Remote execution of simulate_lolbin.sh on {target_host} failed:\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}\n"
        "Run setup_prereqs.sh on the target and verify SSH key-based access."
    )

    audit_alert = wait_for_rule_alert(AUDIT_EXEC_RULE_ID, since_line, timeout=30)
    assert audit_alert is not None, (
        f"Base audit command-execution rule {AUDIT_EXEC_RULE_ID} did not fire. "
        "On the target verify `auditctl -l` contains key audit-wazuh-c, "
        "`/var/log/audit/audit.log` receives EXECVE records, and ossec.conf "
        "collects that file with `<log_format>audit</log_format>`."
    )

    masquerade_alert = wait_for_rule_alert(MASQUERADE_RULE_ID, since_line, timeout=30)
    assert masquerade_alert is not None, (
        f"Audit rule {AUDIT_EXEC_RULE_ID} fired but FAST masquerading rule "
        f"{MASQUERADE_RULE_ID} did not. Inspect the decoded `audit.command` and "
        "`audit.exe` fields for the /tmp/httpd execution on the Manager."
    )

    alert = wait_for_rule_alert(RULE_ID, since_line, timeout=60)
    assert alert is not None, (
        f"FAST masquerading rule {MASQUERADE_RULE_ID} fired but confirmation "
        f"rule {RULE_ID} did not. Inspect the audit event's command arguments "
        "and confirm the wget-style URL/-O evidence is present in the event."
    )
    assert int(alert["rule"]["level"]) >= 6, (
        f"Rule {RULE_ID} fired but at an unexpectedly low level: {alert['rule']}"
    )
