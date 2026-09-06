#!/bin/bash
# ============================================================
# Acceptance Test Prerequisites Setup
# ============================================================
# Run this ONCE, as root, on the TARGET host (the machine running
# the Wazuh Agent that the simulation scripts will attack/exercise -
# NOT on the Wazuh Manager).
#
# It prepares three things the target needs to be attackable/exercisable:
#   1. OpenSSH server for brute-force simulation
#   2. Deterministic kernel logging for FAST port-scan test ports
#   3. auditd execve watch for the later LOLBin simulation
#
# Idempotent: safe to run more than once.
# ============================================================

set -Eeuo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (sudo ./setup_prereqs.sh)." >&2
    exit 1
fi

OSSEC_CONF="/var/ossec/etc/ossec.conf"
AGENT_CONFIG_CHANGED=false
PORTS=(56001 56002 56003 56004 56005 56006 56007 56008 56009 56010 56011 56012)
PORTS_CSV=$(IFS=,; echo "${PORTS[*]}")
FAST_SCAN_PREFIX="FAST_PORTSCAN "

ensure_journald_collection() {
    if [ ! -f "$OSSEC_CONF" ]; then
        echo "[!] Wazuh agent config not found at $OSSEC_CONF; cannot ensure journald collection." >&2
        return 0
    fi

    if grep -Fq '<location>journald</location>' "$OSSEC_CONF"; then
        echo "[OK] Wazuh agent already collects journald"
        return 0
    fi

    cp -a "$OSSEC_CONF" "${OSSEC_CONF}.fast-backup"
    python3 - "$OSSEC_CONF" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
closing = "</ossec_config>"
pos = text.find(closing)
if pos < 0:
    raise SystemExit("No </ossec_config> found in Wazuh agent config")
block = """
  <!-- FAST acceptance tests: collect systemd journal (sshd/kernel logs) -->
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

"""
path.write_text(text[:pos] + block + text[pos:], encoding="utf-8")
PY
    AGENT_CONFIG_CHANGED=true
    echo "[OK] Added journald collection to Wazuh agent config"
}

ensure_fast_portscan_logging() {
    if ! command -v iptables >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y iptables
    fi

    # Tailscale can ACCEPT traffic before UFW's filter rules, which means a
    # scan of a Tailscale 100.x address may never produce a UFW BLOCK record.
    # Log only FAST's reserved test ports in mangle/PREROUTING, before those
    # filter decisions. LOG is non-terminating: it observes packets and does
    # not itself accept/drop traffic or change the target's security policy.
    local rule=(
        -p tcp --syn
        -m multiport --dports "$PORTS_CSV"
        -m limit --limit 30/second --limit-burst 60
        -j LOG --log-prefix "$FAST_SCAN_PREFIX" --log-level 6
    )

    if iptables -t mangle -C PREROUTING "${rule[@]}" 2>/dev/null; then
        echo "[OK] FAST pre-filter port-scan logging rule already present"
    else
        iptables -t mangle -I PREROUTING 1 "${rule[@]}"
        echo "[OK] Added FAST pre-filter port-scan logging rule"
    fi
}

echo "==> [1/3] Installing and enabling OpenSSH server..."
if ! systemctl list-unit-files 2>/dev/null | grep -qE '^(ssh|sshd)\.service'; then
    apt-get update -qq
    apt-get install -y openssh-server
fi
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd
systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd
echo "[OK] sshd is installed and running"

echo ""
echo "==> [2/3] Preparing deterministic port-scan logging..."
ensure_fast_portscan_logging

# Keep explicit UFW deny+log rules as a secondary signal for non-Tailscale
# paths, but FAST detection no longer depends on UFW seeing the packet.
if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y ufw
fi
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw logging medium >/dev/null
for port in "${PORTS[@]}"; do
    ufw deny log "${port}/tcp" >/dev/null 2>&1 || true
done
yes | ufw enable >/dev/null

echo "[OK] UFW is active; FAST test ports are explicitly DENY+LOG: ${PORTS[*]}"
ensure_journald_collection

if [ "$AGENT_CONFIG_CHANGED" = true ]; then
    echo "==> Restarting Wazuh agent to load journald collection..."
    systemctl restart wazuh-agent
    sleep 3
    systemctl is-active --quiet wazuh-agent
    echo "[OK] Wazuh agent restarted"
fi

echo ""
echo "==> [3/3] Installing and configuring auditd (for later LOLBin test)..."
if ! command -v auditctl >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y auditd audispd-plugins
fi

AUDIT_RULE_FILE="/etc/audit/rules.d/wazuh-execve.rules"
if [ ! -f "$AUDIT_RULE_FILE" ] || ! grep -q "audit-wazuh-c" "$AUDIT_RULE_FILE" 2>/dev/null; then
    cat > "$AUDIT_RULE_FILE" << 'EOF'
-a always,exit -F arch=b64 -S execve -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -k audit-wazuh-c
EOF
    augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RULE_FILE"
fi
systemctl enable auditd >/dev/null 2>&1 || true
systemctl restart auditd
echo "[OK] auditd installed and watching execve syscalls (key=audit-wazuh-c)"

echo ""
echo "Prerequisites setup complete."
echo "Port-scan test ports: ${PORTS[*]}"
echo "Kernel marker expected during scan: FAST_PORTSCAN"
echo "Run simulations from the attacking host after pulling the latest FAST code."
