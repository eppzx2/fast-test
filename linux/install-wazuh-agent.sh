#!/bin/bash
# F.A.S.T. - Linux Wazuh Agent installation helper
# Supports Ubuntu/Debian and RHEL/Fedora/CentOS package managers.

set -Eeuo pipefail

WAZUH_VERSION="4.9.0"
MANAGER_IP=""
AGENT_NAME="$(hostname)"
FORCE=false

GREEN="\033[0;32m"; CYAN="\033[0;36m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; NC="\033[0m"
step()    { echo -e "\n${CYAN}==> $*${NC}"; }
success() { echo -e "${GREEN}[OK] $*${NC}"; }
warn()    { echo -e "${YELLOW}[!]  $*${NC}"; }
fail()    { echo -e "${RED}[ERROR] $*${NC}" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip|-i)
            [[ $# -ge 2 && -n "${2:-}" && "${2:-}" != -* ]] || fail "--ip requires a Manager address"
            MANAGER_IP="$2"; shift 2 ;;
        --name|-n)
            [[ $# -ge 2 && -n "${2:-}" && "${2:-}" != -* ]] || fail "--name requires a value"
            AGENT_NAME="$2"; shift 2 ;;
        --force|-f)
            FORCE=true; shift ;;
        -h|--help)
            cat <<EOF
Usage: sudo $0 --ip <MANAGER_IP> [--name <AGENT_NAME>] [--force]

  --force  continue non-interactively when ports 1514/1515 are unreachable
EOF
            exit 0 ;;
        *) fail "Unknown parameter: $1" ;;
    esac
done

[ "$EUID" -eq 0 ] || fail "Run this script with sudo/root privileges"
[ -n "$MANAGER_IP" ] || fail "--ip is required"

if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER=apt
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER=dnf
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER=yum
else
    fail "No supported package manager found (apt/dnf/yum)"
fi

echo "============================================================"
echo -e "  ${CYAN}F.A.S.T. - Linux Wazuh Agent Installation${NC}"
echo "============================================================"
echo "Manager: $MANAGER_IP"
echo "Agent:   $AGENT_NAME"
echo "Version: $WAZUH_VERSION"

step "Checking Manager reachability"
ports_ok=true
for port in 1514 1515; do
    if timeout 5 bash -c ">/dev/tcp/$MANAGER_IP/$port" 2>/dev/null; then
        success "TCP $port reachable"
    else
        warn "TCP $port unreachable"
        ports_ok=false
    fi
done
if [ "$ports_ok" = false ] && [ "$FORCE" = false ]; then
    read -r -p "Continue anyway? (y/N): " answer
    [[ "$answer" =~ ^[Yy]$ ]] || exit 1
fi

step "Installing Wazuh Agent"
if [ "$PKG_MANAGER" = apt ]; then
    apt-get update -qq
    apt-get install -y gnupg curl ca-certificates
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" \
        apt-get install -y "wazuh-agent=$WAZUH_VERSION-1"
else
    cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" \
        "$PKG_MANAGER" install -y "wazuh-agent-$WAZUH_VERSION-1"
fi
success "Wazuh Agent package installed"

OSSEC_CONF=/var/ossec/etc/ossec.conf
[ -f "$OSSEC_CONF" ] || fail "Agent configuration was not created: $OSSEC_CONF"
if ! grep -Fq "<address>$MANAGER_IP</address>" "$OSSEC_CONF"; then
    step "Writing Manager address into ossec.conf"
    sed -i "s|<address>.*</address>|<address>$MANAGER_IP</address>|g" "$OSSEC_CONF"
fi
if command -v xmllint >/dev/null 2>&1; then
    xmllint --noout "$OSSEC_CONF" || fail "Invalid Wazuh agent XML configuration"
fi

step "Starting Wazuh Agent"
systemctl daemon-reload
systemctl enable wazuh-agent >/dev/null
systemctl restart wazuh-agent
sleep 5
systemctl is-active --quiet wazuh-agent || {
    journalctl -u wazuh-agent -n 30 --no-pager || true
    fail "wazuh-agent service did not become active"
}
success "wazuh-agent service is active"

LOG=/var/ossec/logs/ossec.log
step "Checking recent agent connection logs"
sleep 5
if [ -r "$LOG" ]; then
    tail -n 40 "$LOG" | grep -aE 'Connected to the server|Requesting a key|ERROR|WARNING' | tail -12 || true
    if tail -n 80 "$LOG" | grep -aq 'Connected to the server'; then
        success "Agent reports a Manager connection"
    else
        warn "Service is healthy but a confirmed Manager connection was not yet found in recent logs"
    fi
else
    warn "Agent log is not readable: $LOG"
fi

echo ""
echo "DONE. Verify on Manager:"
echo "  docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
