#!/bin/bash
# ============================================================
# Simulate: Nmap-style Port Scan (triggers FAST rule 100211)
# ============================================================
# Probes the deterministic TCP ports prepared by setup_prereqs.sh.
# The target logs SYN packets to these ports in mangle/PREROUTING with
# the FAST_PORTSCAN marker before Tailscale/UFW/filter decisions, so the
# test does not depend on whether a port is later accepted or dropped.
#
# Uses SYN scan when run as root; otherwise uses TCP connect scan.
# Transport/tool failures are not silently reported as success.
#
# USAGE:
#   ./simulate_port_scan.sh <target_host>
# ============================================================

set -Eeuo pipefail

TARGET_HOST="${1:?Usage: $0 <target_host>}"
PORTS=(56001 56002 56003 56004 56005 56006 56007 56008 56009 56010 56011 56012)

echo "==> Simulating port scan against $TARGET_HOST (${#PORTS[@]} FAST test ports)"

if command -v nmap >/dev/null 2>&1; then
    PORT_LIST=$(IFS=,; echo "${PORTS[*]}")
    if [ "$EUID" -eq 0 ]; then
        SCAN_TYPE="-sS"
        echo "  using nmap SYN scan (-sS)"
    else
        SCAN_TYPE="-sT"
        echo "  running without root; using nmap TCP connect scan (-sT)"
    fi

    output=""
    if ! output=$(nmap "$SCAN_TYPE" -Pn -T3 --max-rate 5 --max-retries 0 \
        --host-timeout 45s -p "$PORT_LIST" "$TARGET_HOST" 2>&1); then
        echo "ERROR: nmap failed; no successful port-scan simulation was confirmed." >&2
        printf '%s\n' "$output" | tail -20 >&2
        exit 1
    fi
    echo "[OK] nmap probes sent to ports: $PORT_LIST"
else
    echo "  nmap not found; using bash /dev/tcp fallback"
    for port in "${PORTS[@]}"; do
        # A closed/filtered port naturally makes /dev/tcp return non-zero; that
        # is still a real SYN probe, so only timeout/connection result is ignored.
        timeout 2 bash -c "echo >/dev/tcp/${TARGET_HOST}/${port}" 2>/dev/null || true
        echo "  probed port $port"
        sleep 0.25
    done
    echo "[OK] Probed ${#PORTS[@]} ports via /dev/tcp"
fi

echo "FAST rule 100210 should appear for marked probes; correlation rule 100211 should fire after 8+ probes from one source within 60s."
