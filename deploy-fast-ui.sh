#!/usr/bin/env bash
# ============================================================
# FAST UI preview deployment
# ============================================================
# Deploys the feature/fast-ui dashboard as an isolated Docker
# container bound only to 127.0.0.1, then exposes it through
# Tailscale Funnel over public HTTPS.
#
# This script does NOT run ./bin/fast up and does not modify the
# existing Wazuh/FAST deployment. It is intentionally isolated so
# the current main deployment remains untouched while the UI is
# developed and demonstrated.
#
# Usage:
#   ./deploy-fast-ui.sh
#   FAST_UI_PORT=5001 ./deploy-fast-ui.sh
#
# Optional environment variables:
#   FAST_UI_PORT=5001
#   FAST_UI_DB_SOURCE=/path/to/ioc_database.db
#   FAST_WAZUH_DASHBOARD_URL=https://100.x.y.z
#   FAST_UI_SKIP_UPDATE=1
# ============================================================

set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="feature/fast-ui"
IMAGE="fast-ui-preview:feature"
CONTAINER="fast-ui-preview"
UI_PORT="${FAST_UI_PORT:-5001}"
DATA_DIR="${FAST_UI_DATA_DIR:-$HOME/.local/share/fast-ui-preview}"
DB_TARGET="$DATA_DIR/ioc_database.db"

info() { printf '[FAST UI] %s\n' "$*"; }
warn() { printf '[FAST UI] WARN: %s\n' "$*" >&2; }
fail() { printf '[FAST UI] ERROR: %s\n' "$*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || fail "git is required."
command -v docker >/dev/null 2>&1 || fail "Docker is required."
command -v tailscale >/dev/null 2>&1 || fail "Tailscale is required."
command -v python3 >/dev/null 2>&1 || fail "python3 is required."

docker info >/dev/null 2>&1 || fail "Docker daemon is not running or is not accessible to this user."

mkdir -p "$DATA_DIR"

# Keep the preview checkout current when it is safe to do so. Local changes are
# never discarded automatically.
if [ "${FAST_UI_SKIP_UPDATE:-0}" != "1" ] && git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    CURRENT_BRANCH="$(git -C "$PROJECT_ROOT" branch --show-current 2>/dev/null || true)"
    if [ "$CURRENT_BRANCH" = "$BRANCH" ]; then
        if [ -z "$(git -C "$PROJECT_ROOT" status --porcelain --untracked-files=no)" ]; then
            info "Updating $BRANCH from origin..."
            git -C "$PROJECT_ROOT" pull --ff-only origin "$BRANCH" || warn "Could not fast-forward the branch; continuing with the local checkout."
        else
            warn "Tracked local changes detected; skipping git pull."
        fi
    else
        warn "Current checkout is '$CURRENT_BRANCH', not '$BRANCH'. The script will deploy the files in this checkout without switching branches."
    fi
fi

TAILSCALE_IP="$(tailscale ip -4 2>/dev/null | head -n1 || true)"
[ -n "$TAILSCALE_IP" ] || fail "No Tailscale IPv4 address found. Run 'sudo tailscale up' first."

DNS_NAME="$(tailscale status --json 2>/dev/null | python3 -c 'import json,sys; data=json.load(sys.stdin); print((data.get("Self") or {}).get("DNSName", "").rstrip("."))' 2>/dev/null || true)"
[ -n "$DNS_NAME" ] || fail "Could not determine this node's Tailscale DNS name."

PUBLIC_URL="https://$DNS_NAME"
WAZUH_URL="${FAST_WAZUH_DASHBOARD_URL:-https://$TAILSCALE_IP}"

# Seed the preview with a COPY of the current IOC database. The preview container
# writes only to its own copy, so UI testing cannot modify the working main DB.
DB_SOURCE="${FAST_UI_DB_SOURCE:-}"
if [ -z "$DB_SOURCE" ]; then
    if [ -f "$HOME/fast-test/ioc_database.db" ] && [ "$HOME/fast-test/ioc_database.db" != "$PROJECT_ROOT/ioc_database.db" ]; then
        DB_SOURCE="$HOME/fast-test/ioc_database.db"
    elif [ -f "$PROJECT_ROOT/ioc_database.db" ]; then
        DB_SOURCE="$PROJECT_ROOT/ioc_database.db"
    fi
fi

if [ -n "$DB_SOURCE" ] && [ -f "$DB_SOURCE" ]; then
    info "Copying IOC database snapshot from $DB_SOURCE"
    cp "$DB_SOURCE" "$DB_TARGET.tmp"
    mv "$DB_TARGET.tmp" "$DB_TARGET"
else
    warn "No existing IOC database was found. The preview will start with an empty database."
    rm -f "$DB_TARGET"
fi

info "Building isolated FAST UI image..."
docker build -f "$PROJECT_ROOT/docker/fast-ui.Dockerfile" -t "$IMAGE" "$PROJECT_ROOT"

if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    info "Replacing previous preview container..."
    docker rm -f "$CONTAINER" >/dev/null
fi

ENV_MOUNT=()
if [ -f "$PROJECT_ROOT/.env" ]; then
    # Keep feed credentials out of Docker environment metadata. python-dotenv
    # reads this read-only file inside the container.
    ENV_MOUNT=(-v "$PROJECT_ROOT/.env:/app/.env:ro")
fi

info "Starting FAST UI on local port $UI_PORT..."
docker run -d \
    --name "$CONTAINER" \
    --restart unless-stopped \
    -p "127.0.0.1:${UI_PORT}:5000" \
    -e FAST_WEB_HOST=0.0.0.0 \
    -e FAST_WEB_PORT=5000 \
    -e FAST_WEB_DEBUG=0 \
    -e FAST_DB_PATH=/data/ioc_database.db \
    -e FAST_PUBLIC_URL="$PUBLIC_URL" \
    -e FAST_DEPLOYMENT_MODE=tailscale-funnel \
    -e FAST_WAZUH_DASHBOARD_URL="$WAZUH_URL" \
    -v "$DATA_DIR:/data" \
    "${ENV_MOUNT[@]}" \
    "$IMAGE" >/dev/null

info "Waiting for the UI health check..."
healthy=false
for _ in $(seq 1 30); do
    if docker exec "$CONTAINER" python3 -c "import urllib.request as u; u.urlopen('http://127.0.0.1:5000/api/health', timeout=2).read()" >/dev/null 2>&1; then
        healthy=true
        break
    fi
    sleep 1
done

if [ "$healthy" != true ]; then
    docker logs --tail 80 "$CONTAINER" >&2 || true
    fail "FAST UI did not become healthy."
fi

info "Local UI is healthy at http://127.0.0.1:$UI_PORT"
info "Enabling Tailscale Funnel..."

FUNNEL_LOG="$(mktemp)"
trap 'rm -f "$FUNNEL_LOG"' EXIT

if tailscale funnel --bg --yes "$UI_PORT" >"$FUNNEL_LOG" 2>&1; then
    :
elif command -v sudo >/dev/null 2>&1 && sudo tailscale funnel --bg --yes "$UI_PORT" >"$FUNNEL_LOG" 2>&1; then
    :
else
    cat "$FUNNEL_LOG" >&2 || true
    fail "Tailscale Funnel could not be enabled. Funnel may need to be allowed for this tailnet. The FAST UI container is still running locally on port $UI_PORT."
fi

printf '\n'
printf '============================================================\n'
printf ' FAST UI DEPLOYED\n'
printf '============================================================\n'
printf ' Public URL:      %s\n' "$PUBLIC_URL"
printf ' Local backend:   http://127.0.0.1:%s\n' "$UI_PORT"
printf ' Wazuh button:    %s\n' "$WAZUH_URL"
printf ' Container:       %s\n' "$CONTAINER"
printf ' Database copy:   %s\n' "$DB_TARGET"
printf '============================================================\n'
printf '\nAnyone with the Public URL can open the FAST UI without joining your tailnet.\n'
printf 'The Wazuh button still uses the Tailscale address unless you explicitly configure another URL.\n'
