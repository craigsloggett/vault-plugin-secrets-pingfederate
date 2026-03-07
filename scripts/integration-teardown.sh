#!/usr/bin/env bash
# integration-teardown.sh — Stop Vault and PingFederate container.
set -euo pipefail

CONTAINER_NAME="pingfederate-integration"

echo "=== Integration Test Teardown ==="

# Stop Vault dev server.
echo "Stopping Vault..."
if [ -f /tmp/vault-integration.pid ]; then
    VAULT_PID=$(cat /tmp/vault-integration.pid)
    if kill -0 "${VAULT_PID}" 2>/dev/null; then
        kill "${VAULT_PID}" 2>/dev/null || true
        echo "  Vault stopped (PID: ${VAULT_PID})."
    else
        echo "  Vault process not running."
    fi
    rm -f /tmp/vault-integration.pid
else
    # Fallback: try to kill by process name.
    pkill -f "vault server -dev" 2>/dev/null || echo "  No Vault process found."
fi
rm -f /tmp/vault-integration.log

# Stop PingFederate container (--rm flag auto-removes it on stop).
echo "Stopping PingFederate container..."
container stop "${CONTAINER_NAME}" 2>/dev/null && echo "  PingFederate container stopped." || echo "  PingFederate container not running."

echo "Teardown complete."
