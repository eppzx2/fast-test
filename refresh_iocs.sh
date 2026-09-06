#!/bin/bash
# Refresh threat feeds and the Wazuh CDB list without redeploying FAST.

set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER_CONTAINER="single-node-wazuh.manager-1"
CDB_FILE="$PROJECT_ROOT/sample_output/ioc-ips"
HEALTH_TIMEOUT=60

fail() {
    echo "✗ ERROR: $*" >&2
    exit 1
}

manager_started_at() {
    docker inspect -f '{{.State.StartedAt}}' "$MANAGER_CONTAINER" 2>/dev/null || true
}

manager_healthy() {
    local started_at critical proc_count
    started_at=$(manager_started_at)
    [ -n "$started_at" ] && [ "$started_at" != "0001-01-01T00:00:00Z" ] || return 1
    critical=$(docker logs --since "$started_at" "$MANAGER_CONTAINER" 2>&1 | grep -c CRITICAL || true)
    proc_count=$(docker exec "$MANAGER_CONTAINER" ps aux 2>/dev/null | grep -cE 'wazuh-authd|wazuh-analysisd|wazuh-remoted' || true)
    [ "$critical" -eq 0 ] && [ "$proc_count" -ge 3 ]
}

wait_manager() {
    local elapsed=0
    while [ "$elapsed" -lt "$HEALTH_TIMEOUT" ]; do
        if manager_healthy; then
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    return 1
}

command -v docker >/dev/null 2>&1 || fail "Docker is not installed"
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"
docker image inspect osint-ioc-collector >/dev/null 2>&1 || fail "IOC image is missing; run ./bin/fast up first"
[ "$(docker inspect -f '{{.State.Running}}' "$MANAGER_CONTAINER" 2>/dev/null || echo false)" = true ] || fail "Wazuh Manager container is not running"

echo "===== $(date -u +%Y-%m-%dT%H:%M:%SZ) - IOC refresh started ====="
cd "$PROJECT_ROOT"

collector_env=()
if [ -n "${ABUSECH_AUTH_KEY:-}" ]; then
    # --env NAME forwards the local value without placing it in the command text.
    collector_env=(--env ABUSECH_AUTH_KEY)
else
    echo "⚠️  ABUSECH_AUTH_KEY is not set; MalwareBazaar may use only its compatibility fallback"
fi

# cli.py now returns non-zero when every feed fails or a usable Wazuh export
# cannot be produced, so a bad refresh can never overwrite the live CDB silently.
docker run --rm "${collector_env[@]}" -v "$PROJECT_ROOT:/app" osint-ioc-collector \
    --fetch --export wazuh

[ -s "$CDB_FILE" ] || fail "Fresh CDB export is empty"
if grep -Ev '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?:1$' "$CDB_FILE" | grep -q .; then
    fail "Fresh CDB export contains an invalid line"
fi
echo "✓ Fresh CDB validated ($(wc -l < "$CDB_FILE") entries)"

docker cp "$CDB_FILE" "${MANAGER_CONTAINER}:/var/ossec/etc/lists/ioc-ips"
docker exec "$MANAGER_CONTAINER" /var/ossec/bin/wazuh-analysisd -t >/dev/null || fail "Wazuh analysis configuration rejected the refreshed CDB"

docker restart "$MANAGER_CONTAINER" >/dev/null
echo "⏳ Waiting for Manager after refresh..."
wait_manager || {
    started_at=$(manager_started_at)
    docker logs --since "$started_at" "$MANAGER_CONTAINER" 2>&1 | grep -iE 'CRITICAL|ERROR' | tail -50 || true
    fail "Manager is unhealthy after IOC refresh"
}

docker exec "$MANAGER_CONTAINER" /usr/share/filebeat/bin/filebeat test output -e \
    -c /etc/filebeat/filebeat.yml >/dev/null 2>&1 || fail "Filebeat → Indexer pipeline is unhealthy after refresh"

echo "✓ Manager and Filebeat → Indexer pipeline are healthy"
echo "===== $(date -u +%Y-%m-%dT%H:%M:%SZ) - IOC refresh complete ====="
