#!/usr/bin/env bash
# configure-pingfederate.sh — Create OAuth clients in PingFederate for integration tests.
set -euo pipefail

PF_ADMIN_URL="${PF_ADMIN_URL:-https://localhost:9999}"
PF_ADMIN_USER="${PF_ADMIN_USER:-administrator}"
PING_IDENTITY_PASSWORD="${PING_IDENTITY_PASSWORD:-2FederateM0re}"

# VAULT_ADDR_CONTAINER is the Vault address reachable from inside the PF container
# (via socat bridge on the Apple Containers gateway IP). Falls back to VAULT_ADDR.
VAULT_ADDR_CONTAINER="${VAULT_ADDR_CONTAINER:-${VAULT_ADDR:-http://127.0.0.1:8200}}"

# Shared foothold secret — used for both the OAuth client and the PF admin account.
# Must meet PF's admin password complexity requirements (uppercase, lowercase, digit, special char).
FOOTHOLD_SECRET="V4ult-Test0"

CURL_OPTS=(-sk -H "X-XSRF-Header: PingFederate" -H "Content-Type: application/json" -u "${PF_ADMIN_USER}:${PING_IDENTITY_PASSWORD}")

echo "Configuring PingFederate OAuth clients..."

# Create an Access Token Manager (required before creating OAuth clients).
# PingFederate requires at least one ATM for client_credentials grants.
# Note: ATM id must be alphanumeric only (no hyphens), JWS Algorithm is required.
echo "Creating Access Token Manager..."
atm_response=$(curl "${CURL_OPTS[@]}" -w "\n%{http_code}" \
    "${PF_ADMIN_URL}/pf-admin-api/v1/oauth/accessTokenManagers" \
    -d '{
        "id": "jwtatm",
        "name": "JWT Access Token Manager",
        "pluginDescriptorRef": { "id": "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin" },
        "configuration": {
            "tables": [
                { "name": "Symmetric Keys", "rows": [] },
                { "name": "Certificates", "rows": [] }
            ],
            "fields": [
                { "name": "Token Lifetime", "value": "120" },
                { "name": "Use Centralized Signing Key", "value": "true" },
                { "name": "JWS Algorithm", "value": "RS256" },
                { "name": "Active Symmetric Encryption Key ID", "value": "" },
                { "name": "Active Signing Certificate Key ID", "value": "" },
                { "name": "JWE Algorithm", "value": "" },
                { "name": "JWE Content Encryption Algorithm", "value": "" },
                { "name": "Expand Scope Groups", "value": "false" },
                { "name": "Type Header Value", "value": "" }
            ]
        },
        "attributeContract": {
            "coreAttributes": [],
            "extendedAttributes": [
                { "name": "client_id", "multiValued": false }
            ]
        }
    }' 2>/dev/null)

atm_code=$(echo "$atm_response" | tail -1)
if [ "$atm_code" = "201" ] || [ "$atm_code" = "200" ]; then
    echo "  Access Token Manager created."
elif [ "$atm_code" = "422" ]; then
    echo "  Access Token Manager already exists."
else
    echo "  Warning: ATM creation returned HTTP $atm_code"
    echo "$atm_response" | sed '$d'
fi

# Create an Access Token Mapping (maps client credentials to token attributes).
echo "Creating Access Token Mapping..."
mapping_response=$(curl "${CURL_OPTS[@]}" -w "\n%{http_code}" \
    "${PF_ADMIN_URL}/pf-admin-api/v1/oauth/accessTokenMappings" \
    -d '{
        "id": "default|jwtatm",
        "context": {
            "type": "DEFAULT",
            "contextRef": { "id": "default" }
        },
        "accessTokenManagerRef": { "id": "jwtatm" },
        "attributeContractFulfillment": {
            "client_id": {
                "source": { "type": "CONTEXT" },
                "value": "ClientId"
            }
        },
        "issuanceCriteria": { "conditionalCriteria": [] }
    }' 2>/dev/null)

mapping_code=$(echo "$mapping_response" | tail -1)
if [ "$mapping_code" = "201" ] || [ "$mapping_code" = "200" ]; then
    echo "  Access Token Mapping created."
elif [ "$mapping_code" = "422" ]; then
    echo "  Access Token Mapping already exists."
else
    echo "  Warning: Mapping creation returned HTTP $mapping_code"
    echo "$mapping_response" | sed '$d'
fi

# Create an administrative account matching the foothold's credentials.
# This allows the Vault plugin to use the same credentials for both the
# admin API (Basic Auth) and the token endpoint (client_credentials).
echo "Creating admin account: vault-foothold-secret..."
admin_response=$(curl "${CURL_OPTS[@]}" -w "\n%{http_code}" \
    -X POST \
    "${PF_ADMIN_URL}/pf-admin-api/v1/administrativeAccounts" \
    -d '{
        "username": "vault-foothold-secret",
        "password": "'"${FOOTHOLD_SECRET}"'",
        "active": true,
        "roles": ["ADMINISTRATOR"],
        "auditor": false
    }' 2>/dev/null)

admin_code=$(echo "$admin_response" | tail -1)
admin_body=$(echo "$admin_response" | sed '$d')
if [ "$admin_code" = "201" ] || [ "$admin_code" = "200" ]; then
    echo "  Admin account created."
elif [ "$admin_code" = "422" ]; then
    if echo "$admin_body" | grep -q "already exists"; then
        echo "  Admin account already exists."
    else
        echo "  Warning: Admin account creation returned HTTP 422:"
        echo "  $admin_body"
    fi
else
    echo "  Warning: Admin account creation returned HTTP $admin_code:"
    echo "  $admin_body"
fi

# Delete existing OAuth clients to ensure a clean slate (handles stale container state).
for client_id in vault-foothold-secret vault-foothold-jwt vault-rotate-test target-service-account; do
    curl "${CURL_OPTS[@]}" -o /dev/null -X DELETE "${PF_ADMIN_URL}/pf-admin-api/v1/oauth/clients/${client_id}" 2>/dev/null || true
done

# 1. vault-foothold-secret — client_secret auth for foothold tests.
echo "Creating OAuth client: vault-foothold-secret..."
response=$(curl "${CURL_OPTS[@]}" -w "\n%{http_code}" \
    "${PF_ADMIN_URL}/pf-admin-api/v1/oauth/clients" \
    -d '{
        "clientId": "vault-foothold-secret",
        "name": "Vault Foothold (Secret)",
        "clientAuth": {
            "type": "SECRET",
            "secret": "'"${FOOTHOLD_SECRET}"'"
        },
        "grantTypes": ["CLIENT_CREDENTIALS"],
        "defaultAccessTokenManagerRef": { "id": "jwtatm" }
    }' 2>/dev/null)

code=$(echo "$response" | tail -1)
if [ "$code" = "201" ] || [ "$code" = "200" ]; then
    echo "  Created vault-foothold-secret."
elif [ "$code" = "422" ]; then
    echo "  vault-foothold-secret already exists."
else
    echo "  Error creating vault-foothold-secret (HTTP $code):"
    echo "$response" | sed '$d'
    exit 1
fi

# 2. vault-foothold-jwt — private_key_jwt auth for foothold tests.
#    Created with a jwksUrl placeholder. The PF container cannot reach Vault on
#    the host network, so integration tests that need JWT validation push inline
#    JWKS to this client via the admin API before requesting creds.
echo "Creating OAuth client: vault-foothold-jwt..."
response=$(curl "${CURL_OPTS[@]}" -w "\n%{http_code}" \
    "${PF_ADMIN_URL}/pf-admin-api/v1/oauth/clients" \
    -d '{
        "clientId": "vault-foothold-jwt",
        "name": "Vault Foothold (JWT)",
        "clientAuth": {
            "type": "PRIVATE_KEY_JWT",
            "enforceReplayPrevention": false
        },
        "jwksSettings": {
            "jwksUrl": "'"${VAULT_ADDR_CONTAINER}"'/v1/pingfederate/jwks/test"
        },
        "grantTypes": ["CLIENT_CREDENTIALS"],
        "defaultAccessTokenManagerRef": { "id": "jwtatm" }
    }' 2>/dev/null)

code=$(echo "$response" | tail -1)
if [ "$code" = "201" ] || [ "$code" = "200" ]; then
    echo "  Created vault-foothold-jwt."
elif [ "$code" = "422" ]; then
    echo "  vault-foothold-jwt already exists."
else
    echo "  Error creating vault-foothold-jwt (HTTP $code):"
    echo "$response" | sed '$d'
    exit 1
fi

# 3. vault-rotate-test — dedicated client for rotate-root tests.
#    Isolated from vault-foothold-secret so rotation doesn't poison other tests.
echo "Creating admin account: vault-rotate-test..."
admin_response=$(curl "${CURL_OPTS[@]}" -w "\n%{http_code}" \
    -X POST \
    "${PF_ADMIN_URL}/pf-admin-api/v1/administrativeAccounts" \
    -d '{
        "username": "vault-rotate-test",
        "password": "'"${FOOTHOLD_SECRET}"'",
        "active": true,
        "roles": ["ADMINISTRATOR"],
        "auditor": false
    }' 2>/dev/null)

admin_code=$(echo "$admin_response" | tail -1)
admin_body=$(echo "$admin_response" | sed '$d')
if [ "$admin_code" = "201" ] || [ "$admin_code" = "200" ]; then
    echo "  Admin account created."
elif [ "$admin_code" = "422" ]; then
    if echo "$admin_body" | grep -q "already exists"; then
        echo "  Admin account already exists."
    else
        echo "  Warning: Admin account creation returned HTTP 422:"
        echo "  $admin_body"
    fi
else
    echo "  Warning: Admin account creation returned HTTP $admin_code:"
    echo "  $admin_body"
fi

echo "Creating OAuth client: vault-rotate-test..."
response=$(curl "${CURL_OPTS[@]}" -w "\n%{http_code}" \
    "${PF_ADMIN_URL}/pf-admin-api/v1/oauth/clients" \
    -d '{
        "clientId": "vault-rotate-test",
        "name": "Vault Rotate Test",
        "clientAuth": {
            "type": "SECRET",
            "secret": "'"${FOOTHOLD_SECRET}"'"
        },
        "grantTypes": ["CLIENT_CREDENTIALS"],
        "defaultAccessTokenManagerRef": { "id": "jwtatm" }
    }' 2>/dev/null)

code=$(echo "$response" | tail -1)
if [ "$code" = "201" ] || [ "$code" = "200" ]; then
    echo "  Created vault-rotate-test."
elif [ "$code" = "422" ]; then
    echo "  vault-rotate-test already exists."
else
    echo "  Error creating vault-rotate-test (HTTP $code):"
    echo "$response" | sed '$d'
    exit 1
fi

# 4. target-service-account — target client for static-creds management tests.
echo "Creating OAuth client: target-service-account..."
response=$(curl "${CURL_OPTS[@]}" -w "\n%{http_code}" \
    "${PF_ADMIN_URL}/pf-admin-api/v1/oauth/clients" \
    -d '{
        "clientId": "target-service-account",
        "name": "Target Service Account",
        "clientAuth": {
            "type": "SECRET",
            "secret": "target-service-secret"
        },
        "grantTypes": ["CLIENT_CREDENTIALS"],
        "defaultAccessTokenManagerRef": { "id": "jwtatm" }
    }' 2>/dev/null)

code=$(echo "$response" | tail -1)
if [ "$code" = "201" ] || [ "$code" = "200" ]; then
    echo "  Created target-service-account."
elif [ "$code" = "422" ]; then
    echo "  target-service-account already exists."
else
    echo "  Error creating target-service-account (HTTP $code):"
    echo "$response" | sed '$d'
    exit 1
fi

echo "PingFederate configuration complete."
