#!/bin/bash
# ============================================================
# Simulate: SSH Brute Force (triggers Wazuh rule 100200)
# ============================================================
# Sends repeated wrong-password SSH authentications against the target.
# The script counts only attempts that actually reach the authentication
# stage; connection errors/timeouts are not silently reported as success.
#
# REQUIREMENTS: sshpass installed on the machine running this script;
# the TARGET_HOST must have a Wazuh agent reporting to the Manager.
#
# USAGE:
#   ./simulate_brute_force.sh <target_host> [ssh_user] [attempts]
#
# Example:
#   ./simulate_brute_force.sh 100.87.195.65 testuser 8
# ============================================================

set -Eeuo pipefail

TARGET_HOST="${1:?Usage: $0 <target_host> [ssh_user] [attempts]}"
SSH_USER="${2:-nonexistent_bruteforce_test_user}"
ATTEMPTS="${3:-8}"
MIN_REAL_FAILURES=5

command -v sshpass >/dev/null 2>&1 || {
    echo "ERROR: sshpass is required. Install with: sudo apt-get install -y sshpass" >&2
    exit 1
}

echo "==> Simulating SSH brute force against $TARGET_HOST ($ATTEMPTS attempts, user=$SSH_USER)"

real_failures=0
for i in $(seq 1 "$ATTEMPTS"); do
    output=""
    rc=0
    output=$(sshpass -p "definitely-wrong-password-$RANDOM" \
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 \
            -o NumberOfPasswordPrompts=1 \
            -o PasswordAuthentication=yes \
            -o KbdInteractiveAuthentication=no \
            -o PreferredAuthentications=password \
            "${SSH_USER}@${TARGET_HOST}" "true" 2>&1) || rc=$?

    # ssh returns 255 both for expected auth rejection and for transport
    # failures, so distinguish them from the text instead of hiding all errors.
    if printf '%s\n' "$output" | grep -qiE 'Permission denied|authentication failed|invalid user'; then
        real_failures=$((real_failures + 1))
        echo "  attempt $i/$ATTEMPTS: authentication rejected ($real_failures real failures)"
    else
        echo "  attempt $i/$ATTEMPTS: did not reach a verifiable password failure (ssh rc=$rc)" >&2
        if [ -n "$output" ]; then
            printf '    %s\n' "$(printf '%s\n' "$output" | tail -1)" >&2
        fi
    fi

    # Avoid hammering OpenSSH's per-source penalties so fast that later TCP
    # connections are rejected before an authentication event is generated.
    sleep 1
 done

if [ "$real_failures" -lt "$MIN_REAL_FAILURES" ]; then
    echo "ERROR: Only $real_failures real SSH authentication failures were observed; need at least $MIN_REAL_FAILURES for FAST rule 100200." >&2
    echo "Check PasswordAuthentication on the target and OpenSSH per-source penalties, then retry." >&2
    exit 1
fi

echo "[OK] Generated $real_failures real failed SSH authentications. FAST rule 100200 should fire within 60s."
