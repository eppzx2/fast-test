"""Canonical FAST detection catalogue shared by the API and UI."""

DETECTIONS = [
    {
        "id": "100200",
        "name": "SSH Failed Authentication",
        "attack_type": "SSH brute-force",
        "level": 10,
        "mitre": ["T1110"],
        "description": "Promotes Wazuh rule 5760 failed SSH authentication events into the FAST detection namespace.",
        "status": "enabled",
        "validation_command": "./tests/acceptance/sim/simulate_brute_force.sh <TARGET_IP> nonexistent_bruteforce_test_user 8",
        "validation_host": "runner",
    },
    {
        "id": "100211",
        "name": "Port Scan",
        "attack_type": "Port scan",
        "level": 7,
        "mitre": ["T1046"],
        "description": "Correlates 8 or more FAST_PORTSCAN probes from the same source IP within 60 seconds.",
        "status": "enabled",
        "validation_command": "./tests/acceptance/sim/simulate_port_scan.sh <TARGET_IP>",
        "validation_host": "runner",
    },
    {
        "id": "100221",
        "name": "LOLBin / Masquerading",
        "attack_type": "LOLBin / masquerading",
        "level": 12,
        "mitre": ["T1036.003", "T1105"],
        "description": "Confirms a process presenting as httpd from a non-standard path with wget-style command-line evidence.",
        "status": "enabled",
        "validation_command": "./tests/acceptance/sim/simulate_lolbin.sh",
        "validation_host": "target",
    },
]

DETECTION_BY_ID = {item["id"]: item for item in DETECTIONS}
