#!/usr/bin/env bash
# integration-teardown.sh — Stop Vault, socat bridge, and PingFederate container.
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

# Stop socat bridge.
echo "Stopping socat bridge..."
if [ -f /tmp/socat-integration.pid ]; then
    SOCAT_PID=$(cat /tmp/socat-integration.pid)
    if kill -0 "${SOCAT_PID}" 2>/dev/null; then
        kill "${SOCAT_PID}" 2>/dev/null || true
        echo "  socat stopped (PID: ${SOCAT_PID})."
    else
        echo "  socat process not running."
    fi
    rm -f /tmp/socat-integration.pid
else
    pkill -f "socat TCP-LISTEN:8200" 2>/dev/null || echo "  No socat process found."
fi

# Stop PingFederate container (--rm flag auto-removes it on stop).
echo "Stopping PingFederate container..."
container stop "${CONTAINER_NAME}" 2>/dev/null && echo "  PingFederate container stopped." || echo "  PingFederate container not running."

echo "Teardown complete."
