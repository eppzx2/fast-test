#!/bin/bash
# ============================================================
# F.A.S.T. - IOC Refresh Script
# ============================================================
# Without repeating deploy.sh's full setup steps, this only
# re-collects IOCs and pushes them to Wazuh.
#
# Usage: ./refresh_iocs.sh
# Example for cron (every day at 03:00):
#   0 3 * * * /path/to/osint-ioc-collector/refresh_iocs.sh >> /var/log/fast-refresh.log 2>&1
# ============================================================
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER_CONTAINER="single-node-wazuh.manager-1"

manager_started_at() {
    docker inspect -f '{{.State.StartedAt}}' "$MANAGER_CONTAINER" 2>/dev/null || true
}

echo "===== $(date -u +%Y-%m-%dT%H:%M:%SZ) - IOC refresh started ====="
cd "$PROJECT_ROOT"

docker run --rm -v "$PROJECT_ROOT:/app" osint-ioc-collector \
    --fetch --export wazuh

docker cp "$PROJECT_ROOT/sample_output/ioc-ips" "${MANAGER_CONTAINER}:/var/ossec/etc/lists/ioc-ips"
docker restart "$MANAGER_CONTAINER" >/dev/null

echo "⏳ Checking health after the restart (20 seconds)..."
sleep 20

started_at=$(manager_started_at)
if [ -n "$started_at" ] && [ "$started_at" != "0001-01-01T00:00:00Z" ]; then
    critical_errors=$(docker logs --since "$started_at" "$MANAGER_CONTAINER" 2>&1 | grep -c "CRITICAL" || true)
else
    critical_errors=1
fi

proc_count=$(docker exec "$MANAGER_CONTAINER" ps aux 2>/dev/null | grep -cE "wazuh-authd|wazuh-analysisd|wazuh-remoted" || true)

if [ "$critical_errors" -eq 0 ] && [ "$proc_count" -ge 3 ]; then
    echo "✓ Manager is healthy"
else
    echo "⚠️  WARNING: The Manager does not appear healthy after the restart."
    echo "   Current-start Manager errors:"
    if [ -n "$started_at" ] && [ "$started_at" != "0001-01-01T00:00:00Z" ]; then
        docker logs --since "$started_at" "$MANAGER_CONTAINER" 2>&1 | grep -iE "CRITICAL|ERROR" | tail -50 || true
    else
        docker logs --tail 50 "$MANAGER_CONTAINER" 2>&1 || true
    fi
    exit 1
fi

echo "===== $(date -u +%Y-%m-%dT%H:%M:%SZ) - IOC refresh complete ====="
