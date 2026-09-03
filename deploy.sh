#!/bin/bash
# ============================================================
# F.A.S.T. - OSINT Threat Aggregation + Wazuh SIEM
# Single-Script Fast Deployment
# ============================================================
#
# This script does the following:
#   1. Downloads the official Wazuh Docker stack (Manager+Indexer+Dashboard)
#      (first run only - this step is skipped on later runs)
#   2. Generates certificates (first run only)
#   3. Starts the Wazuh stack with a FULLY DEFAULT configuration
#   4. Verifies the initial Manager state (authd/analysisd/remoted)
#   5. Builds the IOC Collector image and runs the first collection
#   6. Installs the CDB list + custom rules, validates them with analysisd -t
#   7. Restarts the Manager once and verifies the final healthy state
#
# REQUIREMENTS: Docker + Docker Compose plugin must be installed
#
# USAGE: ./deploy.sh [--ip <MANAGER_IP>]
#   --ip <IP>   Manually set the Manager's IP (to display for agents).
#               If not provided, it's auto-detected: first the Tailscale
#               IP, if not found the public IP, if not found the local IP.
# TO REFRESH (only update IOCs): ./refresh_iocs.sh
# ============================================================

set -e

# --- Parse parameters ---
MANAGER_IP_OVERRIDE=""
DEMO_MODE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip|-i)
            MANAGER_IP_OVERRIDE="$2"
            shift 2
            ;;
        --demo)
            DEMO_MODE=true
            shift
            ;;
        -h|--help)
            echo "Usage: ./deploy.sh [--ip <MANAGER_IP>] [--demo]"
            echo ""
            echo "  --ip <IP>   Manually set the Manager's IP."
            echo "              If not provided, it's auto-detected."
            echo "  --demo      Seed IOCs from the bundled fixture"
            echo "              (sample_output/ioc_export.json) instead of"
            echo "              fetching live feeds. No network calls to"
            echo "              external feeds are made in this mode."
            exit 0
            ;;
        *)
            echo "✗ Unknown parameter: $1 (see: ./deploy.sh --help)"
            exit 1
            ;;
    esac
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_DIR="$PROJECT_ROOT/wazuh-docker"
WAZUH_VERSION="v4.9.0"
WAZUH_MANAGER_CONF="$WAZUH_DIR/single-node/config/wazuh_cluster/wazuh_manager.conf"
MANAGER_CONTAINER="single-node-wazuh.manager-1"
HEALTH_CHECK_TIMEOUT=90
HEALTH_CHECK_INTERVAL=5

echo "════════════════════════════════════════════════════════"
echo "  F.A.S.T. - Deployment Starting"
echo "════════════════════════════════════════════════════════"

command -v docker >/dev/null 2>&1 || { echo "✗ Docker is not installed. Install it: https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "✗ Docker Compose plugin not found."; exit 1; }
command -v git >/dev/null 2>&1 || { echo "✗ Git is not installed."; exit 1; }

echo "✓ Docker, Docker Compose, Git are available"
echo ""

_is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    local -a octets=($ip)
    for octet in "${octets[@]}"; do
        [ "$octet" -le 255 ] || return 1
    done
    return 0
}

detect_manager_ip() {
    if [ -n "$MANAGER_IP_OVERRIDE" ]; then
        echo "$MANAGER_IP_OVERRIDE"
        return
    fi

    if command -v tailscale >/dev/null 2>&1; then
        local ts_ip
        ts_ip=$(tailscale ip -4 2>/dev/null | head -1)
        if _is_valid_ipv4 "$ts_ip"; then
            echo "$ts_ip"
            return
        fi
    fi

    local pub_ip
    pub_ip=$(curl -sf --max-time 5 https://ifconfig.me 2>/dev/null)
    if _is_valid_ipv4 "$pub_ip"; then
        echo "$pub_ip"
        return
    fi

    local local_ip
    local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if _is_valid_ipv4 "$local_ip"; then
        echo "$local_ip"
        return
    fi

    echo ""
}

# Docker keeps a container's log history across `docker restart`. Looking at
# unbounded `docker logs` therefore makes an old CRITICAL line poison every
# future health check. Always scope log checks to the CURRENT container start.
manager_started_at() {
    docker inspect -f '{{.State.StartedAt}}' "$MANAGER_CONTAINER" 2>/dev/null || true
}

manager_current_critical_count() {
    local started_at
    started_at=$(manager_started_at)

    if [ -z "$started_at" ] || [ "$started_at" = "0001-01-01T00:00:00Z" ]; then
        echo "1"
        return
    fi

    docker logs --since "$started_at" "$MANAGER_CONTAINER" 2>&1 | grep -c "CRITICAL" || true
}

show_manager_current_errors() {
    local started_at
    started_at=$(manager_started_at)

    echo "  Manager errors from the current container start:"
    if [ -n "$started_at" ] && [ "$started_at" != "0001-01-01T00:00:00Z" ]; then
        docker logs --since "$started_at" "$MANAGER_CONTAINER" 2>&1 | grep -iE "CRITICAL|ERROR" | tail -50 || true
    else
        docker logs --tail 50 "$MANAGER_CONTAINER" 2>&1 || true
    fi
}

wait_for_manager_healthy() {
    local elapsed=0
    echo "🔍 Checking Manager health..."

    while [ "$elapsed" -lt "$HEALTH_CHECK_TIMEOUT" ]; do
        local critical_errors proc_count
        critical_errors=$(manager_current_critical_count)
        proc_count=$(docker exec "$MANAGER_CONTAINER" ps aux 2>/dev/null | grep -cE "wazuh-authd|wazuh-analysisd|wazuh-remoted" || true)

        if [ "$critical_errors" -eq 0 ] && [ "$proc_count" -ge 3 ]; then
            echo "✓ Manager is healthy (current start: authd, analysisd, remoted running; no CRITICAL errors)"
            return 0
        fi

        sleep "$HEALTH_CHECK_INTERVAL"
        elapsed=$((elapsed + HEALTH_CHECK_INTERVAL))
        echo "  ... waiting (${elapsed}s/${HEALTH_CHECK_TIMEOUT}s)"
    done

    echo "✗ ERROR: Manager did not become healthy within ${HEALTH_CHECK_TIMEOUT} seconds."
    show_manager_current_errors
    return 1
}

# Wazuh requires every CDB list referenced from a rule to also be registered
# inside the <ruleset> block of ossec.conf. The official v4.9.0 Docker stack
# bind-mounts this file into the Manager on every container start, so update
# the mounted source file idempotently.
ensure_ioc_list_registered() {
    local marker="<list>etc/lists/ioc-ips</list>"
    local tmp_file="${WAZUH_MANAGER_CONF}.fast.$$"

    if grep -Fq "$marker" "$WAZUH_MANAGER_CONF"; then
        echo "✓ Wazuh CDB list is already registered in ossec.conf"
        return 0
    fi

    if awk -v marker="$marker" '
        BEGIN { inserted = 0 }
        !inserted && /<\/ruleset>/ {
            print "    " marker
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 42 }
    ' "$WAZUH_MANAGER_CONF" > "$tmp_file"; then
        mv "$tmp_file" "$WAZUH_MANAGER_CONF"
        echo "✓ Registered etc/lists/ioc-ips in Wazuh <ruleset>"
    else
        rm -f "$tmp_file"
        echo "✗ ERROR: Could not register etc/lists/ioc-ips in $WAZUH_MANAGER_CONF" >&2
        return 1
    fi
}

validate_manager_configuration() {
    echo "🧪 Validating Wazuh rules/configuration before restart..."
    if docker exec "$MANAGER_CONTAINER" /var/ossec/bin/wazuh-analysisd -t; then
        echo "✓ Wazuh analysis configuration is valid"
        return 0
    fi

    echo "✗ ERROR: Wazuh rule/config validation failed. Manager will NOT be restarted." >&2
    return 1
}

if [ ! -d "$WAZUH_DIR" ]; then
    echo "📥 Downloading the Wazuh Docker stack ($WAZUH_VERSION)..."
    git clone --branch "$WAZUH_VERSION" --depth 1 https://github.com/wazuh/wazuh-docker.git "$WAZUH_DIR"
else
    echo "✓ Wazuh Docker stack already exists ($WAZUH_DIR)"
fi

cd "$WAZUH_DIR/single-node"

if [ ! -d "config/wazuh_indexer_ssl_certs" ] || [ -z "$(ls -A config/wazuh_indexer_ssl_certs 2>/dev/null)" ]; then
    echo ""
    echo "🔐 Generating SSL certificates..."
    docker compose -f generate-indexer-certs.yml run --rm generator
else
    echo "✓ Certificates already exist"
fi

echo "🩺 Applying container healthcheck definitions (no volumes, safe to reuse)..."
cp "$PROJECT_ROOT/docker/healthcheck.override.yml" "./docker-compose.override.yml"

echo ""
echo "🚀 Starting Wazuh Manager + Indexer + Dashboard..."
docker compose up -d

echo ""
echo "⏳ Waiting for containers to start (15 seconds)..."
sleep 15

# A previously broken custom rule can leave analysisd down in the persistent
# Wazuh volume. If the container itself is still running, continue so this
# deployment can replace/repair FAST's custom assets and validate them.
if ! wait_for_manager_healthy; then
    manager_running=$(docker inspect -f '{{.State.Running}}' "$MANAGER_CONTAINER" 2>/dev/null || echo "false")
    if [ "$manager_running" = "true" ]; then
        echo "⚠️  Manager is currently degraded, but the container is running."
        echo "   Continuing with FAST rule/CDB repair before the final restart."
    else
        echo "✗ Deployment stopped - the Manager container is not running."
        exit 1
    fi
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  TALON IOC Collector - First Collection"
echo "════════════════════════════════════════════════════════"
cd "$PROJECT_ROOT"

echo "🔨 Building the IOC Collector image..."
docker build -t osint-ioc-collector -f docker/ioc-collector.Dockerfile .

echo ""
if [ "$DEMO_MODE" = true ]; then
    echo "📦 DEMO mode: seeding IOCs from sample_output/ioc_export.json (no network calls)..."
    docker run --rm -v "$PROJECT_ROOT:/app" osint-ioc-collector --init-db
    docker run --rm -v "$PROJECT_ROOT:/app" --entrypoint python3 osint-ioc-collector -c "
import json, sys
sys.path.insert(0, '/app')
from core import db
db.init_database()
with open('/app/sample_output/ioc_export.json') as f:
    fixture = json.load(f)
for row in fixture:
    row.pop('id', None)
    row.pop('confidence_score', None)
count = db.insert_batch(fixture)
print(f'Seeded {count} IOCs from fixture')
"
    docker run --rm -v "$PROJECT_ROOT:/app" osint-ioc-collector --export wazuh
else
    echo "📡 Collecting from feeds, normalizing, exporting to Wazuh CDB..."
    docker run --rm -v "$PROJECT_ROOT:/app" osint-ioc-collector \
        --init-db --fetch --export wazuh
fi

echo ""
echo "🔗 Installing FAST CDB list and custom detection rules..."

docker cp "$PROJECT_ROOT/sample_output/ioc-ips" "${MANAGER_CONTAINER}:/var/ossec/etc/lists/ioc-ips"
ensure_ioc_list_registered

docker cp "$WAZUH_MANAGER_CONF" "${MANAGER_CONTAINER}:/var/ossec/etc/ossec.conf"
docker cp "$PROJECT_ROOT/docker/rules/local_rules.xml" "${MANAGER_CONTAINER}:/var/ossec/etc/rules/local_rules.xml"

if ! validate_manager_configuration; then
    echo "  Fix docker/rules/local_rules.xml (or the CDB registration) and run ./bin/fast up again."
    exit 1
fi

echo ""
echo "🔄 Restarting Wazuh Manager once to load the validated rules and CDB list..."
docker restart "$MANAGER_CONTAINER" >/dev/null

echo "⏳ Checking health after the final restart..."
sleep 10
if ! wait_for_manager_healthy; then
    echo "✗ Deployment failed - Manager is unhealthy after loading FAST rules/CDB."
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ DEPLOYMENT COMPLETE"
echo "════════════════════════════════════════════════════════"

DETECTED_IP=$(detect_manager_ip)

echo ""
echo "Wazuh Dashboard:  https://${DETECTED_IP:-localhost}"
echo "  Username: admin"
echo "  Password: SecretPassword (change it on first login!)"
echo ""

if [ -n "$DETECTED_IP" ]; then
    echo "────────────────────────────────────────────────────────"
    echo "  Manager IP for Agent Connection: $DETECTED_IP"
    echo "────────────────────────────────────────────────────────"
    echo ""
    echo "To connect from a Windows host (PowerShell, Administrator):"
    echo "  cd windows"
    echo "  .\\install-wazuh-agent.ps1 -ManagerIP \"$DETECTED_IP\""
    echo ""
    echo "To connect from a Linux target:"
    echo "  cd linux"
    echo "  sudo ./install-wazuh-agent.sh --ip $DETECTED_IP"
else
    echo "⚠️  The Manager IP could not be auto-detected."
    echo "   Set it manually next time: ./deploy.sh --ip <IP_ADDRESS>"
    echo ""
fi

echo "To refresh IOCs: ./refresh_iocs.sh"
echo "To stop the stack: cd wazuh-docker/single-node && docker compose down"
