#!/usr/bin/env bash
# integration-setup.sh — Build plugin, start PingFederate container, start Vault, configure everything.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Load optional env file.
if [ -f "${PROJECT_DIR}/.env.integration" ]; then
    # shellcheck disable=SC1091
    source "${PROJECT_DIR}/.env.integration"
fi

export PING_IDENTITY_PASSWORD="${PING_IDENTITY_PASSWORD:-2FederateM0re}"
export PF_ADMIN_URL="https://localhost:9999"
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"

# Apple Containers network gateway — used by PingFederate (inside the container)
# to reach Vault (on the host). Vault binds to 0.0.0.0 so it is directly
# reachable on the bridge100 interface.
CONTAINER_GATEWAY_IP="192.168.64.1"
export VAULT_ADDR_CONTAINER="http://${CONTAINER_GATEWAY_IP}:8200"

CONTAINER_NAME="pingfederate-integration"

echo "=== Integration Test Setup ==="

# Step 1: Build the plugin.
echo ""
echo "--- Building plugin ---"
cd "${PROJECT_DIR}"
make build

# Step 2: Start PingFederate container.
echo ""
echo "--- Starting PingFederate container ---"

# Stop any existing container.
if container list -q 2>/dev/null | grep -q "${CONTAINER_NAME}"; then
    echo "Stopping existing PingFederate container..."
    container stop "${CONTAINER_NAME}" 2>/dev/null || true
fi

container run \
    --rm \
    --name "${CONTAINER_NAME}" \
    --publish 9999:9999 \
    --publish 9031:9031 \
    --env "PING_IDENTITY_ACCEPT_EULA=YES" \
    --env "CREATE_INITIAL_ADMIN_USER=true" \
    --env "PING_IDENTITY_PASSWORD=${PING_IDENTITY_PASSWORD}" \
    --detach \
    pingfederate:latest

echo "PingFederate container started."

# Step 3: Wait for PingFederate to be healthy.
echo ""
echo "--- Waiting for PingFederate health check ---"
MAX_WAIT=120
ELAPSED=0
until curl -sk -u "administrator:${PING_IDENTITY_PASSWORD}" -H "X-XSRF-Header: PingFederate" -o /dev/null -w "%{http_code}" "${PF_ADMIN_URL}/pf-admin-api/v1/version" 2>/dev/null | grep -q "200"; do
    if [ "${ELAPSED}" -ge "${MAX_WAIT}" ]; then
        echo "ERROR: PingFederate did not become healthy within ${MAX_WAIT}s."
        exit 1
    fi
    echo "  Waiting for PingFederate... (${ELAPSED}s/${MAX_WAIT}s)"
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done
echo "PingFederate is healthy."

# Step 4: Start Vault dev server.
echo ""
echo "--- Starting Vault dev server ---"

# Kill any existing Vault dev server.
pkill -f "vault server -dev" 2>/dev/null || true
sleep 1

vault server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200 -dev-plugin-dir="${PROJECT_DIR}/bin" > /tmp/vault-integration.log 2>&1 &
VAULT_PID=$!
echo "${VAULT_PID}" > /tmp/vault-integration.pid

# Wait for Vault to be ready.
ELAPSED=0
until vault status > /dev/null 2>&1; do
    if [ "${ELAPSED}" -ge 30 ]; then
        echo "ERROR: Vault did not start within 30s."
        cat /tmp/vault-integration.log
        exit 1
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
echo "Vault is ready (PID: ${VAULT_PID})."

# Step 5: Enable the plugin.
echo ""
echo "--- Enabling plugin ---"
vault secrets enable -path=pingfederate vault-plugin-secrets-pingfederate
echo "Plugin enabled at pingfederate/."

# Step 6: Configure PingFederate OAuth clients.
echo ""
echo "--- Configuring PingFederate OAuth clients ---"
bash "${SCRIPT_DIR}/configure-pingfederate.sh"

# Step 7: Set up Vault identity for token brokering tests.
echo ""
echo "--- Setting up Vault identity ---"

# Enable userpass auth.
vault auth enable userpass 2>/dev/null || echo "  userpass already enabled."

# Create a policy granting access to the plugin paths.
vault policy write integration-test - <<'POLICY'
path "pingfederate/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
POLICY
echo "  Policy created."

# Create a test user with the integration-test policy.
vault write auth/userpass/users/integration-test-user password=testpassword policies=integration-test

# Create a Vault entity with metadata.
ENTITY_RESPONSE=$(vault write -format=json identity/entity \
    name="integration-test-entity" \
    metadata="team=platform" \
    metadata="env=test")
ENTITY_ID=$(echo "${ENTITY_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['id'])")
echo "  Entity created: ${ENTITY_ID}"

# Get the userpass mount accessor.
ACCESSOR=$(vault auth list -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['userpass/']['accessor'])")

# Create an entity alias linking the user to the entity.
vault write identity/entity-alias \
    name="integration-test-user" \
    canonical_id="${ENTITY_ID}" \
    mount_accessor="${ACCESSOR}"
echo "  Entity alias created."

# Step 8: Create default roles for integration tests.
echo ""
echo "--- Creating default roles ---"

# Create a brokered token role pointing to the "test" connection.
# The integration tests will create their own connections and roles as needed,
# but having a default available simplifies some test flows.
vault write pingfederate/roles/test-role connection_name=test 2>/dev/null || echo "  Role test-role skipped (connection may not exist yet)."
echo "  Default roles configured."

echo ""
echo "=== Setup complete ==="
echo "  PingFederate: ${PF_ADMIN_URL}"
echo "  Vault:        ${VAULT_ADDR}"
echo "  Vault (container): ${VAULT_ADDR_CONTAINER}"
echo "  Vault Token:  ${VAULT_TOKEN}"
