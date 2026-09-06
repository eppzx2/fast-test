"""
Acceptance test: FAST deterministic port scan -> Wazuh rules 100210/100211.

The target must first run tests/acceptance/sim/setup_prereqs.sh. That installs
a narrow pre-filter kernel LOG marker (FAST_PORTSCAN) for the reserved test
ports and ensures journald collection. This avoids depending on whether
Tailscale/UFW happens to accept or drop the probe later in the filter path.
"""

import os
import subprocess
from pathlib import Path

import pytest

BASE_RULE_ID = 100210
RULE_ID = 100211
SIM_SCRIPT = Path(__file__).parent / "sim" / "simulate_port_scan.sh"


def test_port_scan_triggers_rule_100211(alert_line_count, wait_for_rule_alert):
    target_host = os.environ.get("TARGET_HOST")
    if not target_host:
        pytest.skip(
            "TARGET_HOST env var not set - point it at the Linux target with a "
            "Wazuh agent, e.g. TARGET_HOST=1.2.3.4"
        )

    since_line = alert_line_count()

    result = subprocess.run(
        ["bash", str(SIM_SCRIPT), target_host],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"simulate_port_scan.sh failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )

    base_alert = wait_for_rule_alert(BASE_RULE_ID, since_line, timeout=20)
    assert base_alert is not None, (
        f"FAST base rule {BASE_RULE_ID} did not fire. On the target, rerun "
        "setup_prereqs.sh and verify `journalctl -k` contains FAST_PORTSCAN "
        "for the scan. If the marker exists locally but not in Wazuh, verify "
        "the agent's journald collection."
    )

    alert = wait_for_rule_alert(RULE_ID, since_line, timeout=60)
    assert alert is not None, (
        f"FAST base rule {BASE_RULE_ID} fired, but correlation rule {RULE_ID} "
        "did not. Verify that 8+ FAST_PORTSCAN events from the same srcip were "
        "received within 60 seconds and that the deployed local_rules.xml is current."
    )
    assert int(alert["rule"]["level"]) >= 5, (
        f"Rule {RULE_ID} fired but at an unexpectedly low level: {alert['rule']}"
    )
