"""
Acceptance test: SSH brute force -> FAST rule 100200.

Requires TARGET_HOST (a host with a Wazuh agent reporting to the
Manager). Skips (does not fail) if TARGET_HOST is not set, or if the
Wazuh Manager isn't running (see conftest.py).
"""

import os
import subprocess
from pathlib import Path

import pytest

RULE_ID = 100200
BASE_RULE_ID = 5760
SIM_SCRIPT = Path(__file__).parent / "sim" / "simulate_brute_force.sh"


def test_ssh_brute_force_triggers_rule_100200(alert_line_count, wait_for_rule_alert):
    target_host = os.environ.get("TARGET_HOST")
    if not target_host:
        pytest.skip(
            "TARGET_HOST env var not set - point it at a host with a "
            "Wazuh agent reachable over SSH, e.g. TARGET_HOST=1.2.3.4"
        )

    ssh_user = os.environ.get("BRUTE_FORCE_SSH_USER", "nonexistent_bruteforce_test_user")
    since_line = alert_line_count()

    # Use a few attempts above the FAST 5-event threshold. The simulator itself
    # verifies that at least five attempts really reached password auth.
    result = subprocess.run(
        ["bash", str(SIM_SCRIPT), target_host, ssh_user, "8"],
        capture_output=True, text=True, timeout=90,
    )
    assert result.returncode == 0, (
        f"simulate_brute_force.sh failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )

    # Wazuh v4.9 classifies the failed-password event as rule 5760. FAST rule
    # 100200 intentionally correlates five of those events from one source.
    base_alert = wait_for_rule_alert(BASE_RULE_ID, since_line, timeout=15)
    assert base_alert is not None, (
        f"Wazuh base rule {BASE_RULE_ID} did not appear after the simulation. "
        "The failure is before FAST correlation: verify sshd/journald collection "
        "on the target and agent connectivity to the Manager."
    )

    alert = wait_for_rule_alert(RULE_ID, since_line, timeout=60)
    assert alert is not None, (
        f"Wazuh rule {BASE_RULE_ID} fired, but FAST rule {RULE_ID} did not. "
        "Rule 100200 must correlate five rule-5760 events from the same srcip "
        "within 60 seconds; verify the deployed local_rules.xml matches GitHub main."
    )
    assert int(alert["rule"]["level"]) >= 5, (
        f"Rule {RULE_ID} fired but at an unexpectedly low level: {alert['rule']}"
    )
