//go:build integration

package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
)

const (
	pfAdminURL      = "https://localhost:9999"
	pfTokenURL      = "https://localhost:9031/as/token.oauth2"
	pfAdminUser     = "administrator"
	pfAdminPassword = "2FederateM0re"
	pluginPath      = "pingfederate"
	footholdSecret  = "V4ult-Test0"
	testUser        = "integration-test-user"
	testPassword    = "testpassword"
)

// vaultClient returns a Vault API client authenticated with the root token.
func vaultClient(t *testing.T) *api.Client {
	t.Helper()

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		token = "root"
	}

	cfg := api.DefaultConfig()
	cfg.Address = addr

	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create Vault client: %v", err)
	}
	client.SetToken(token)

	return client
}

// vaultUserClient authenticates as the test user via userpass and returns a client
// with the resulting token (which carries entity context).
func vaultUserClient(t *testing.T) *api.Client {
	t.Helper()

	client := vaultClient(t)

	// Authenticate via userpass to get a token with entity context.
	secret, err := client.Logical().Write("auth/userpass/login/"+testUser, map[string]any{
		"password": testPassword,
	})
	if err != nil {
		t.Fatalf("failed to login as test user: %v", err)
	}
	if secret == nil || secret.Auth == nil {
		t.Fatal("userpass login returned nil auth")
	}

	client.SetToken(secret.Auth.ClientToken)
	return client
}

// writePluginConfig writes config for a named connection.
func writePluginConfig(t *testing.T, client *api.Client, connName string, data map[string]any) *api.Secret {
	t.Helper()

	secret, err := client.Logical().Write(pluginPath+"/config/"+connName, data)
	if err != nil {
		t.Fatalf("failed to write plugin config %q: %v", connName, err)
	}
	return secret
}

// readPluginConfig reads config for a named connection.
func readPluginConfig(t *testing.T, client *api.Client, connName string) *api.Secret {
	t.Helper()

	secret, err := client.Logical().Read(pluginPath + "/config/" + connName)
	if err != nil {
		t.Fatalf("failed to read plugin config %q: %v", connName, err)
	}
	return secret
}

// deletePluginConfig deletes a named connection config.
func deletePluginConfig(t *testing.T, client *api.Client, connName string) {
	t.Helper()

	_, err := client.Logical().Delete(pluginPath + "/config/" + connName)
	if err != nil {
		t.Fatalf("failed to delete plugin config %q: %v", connName, err)
	}
}

// writePluginRole writes a role for brokered token generation.
func writePluginRole(t *testing.T, client *api.Client, roleName string, data map[string]any) *api.Secret {
	t.Helper()

	secret, err := client.Logical().Write(pluginPath+"/roles/"+roleName, data)
	if err != nil {
		t.Fatalf("failed to write plugin role %q: %v", roleName, err)
	}
	return secret
}

// deletePluginRole deletes a role.
func deletePluginRole(t *testing.T, client *api.Client, roleName string) {
	t.Helper()

	_, err := client.Logical().Delete(pluginPath + "/roles/" + roleName)
	if err != nil {
		t.Fatalf("failed to delete plugin role %q: %v", roleName, err)
	}
}

// skipIfNotReady skips the test if Vault or PingFederate aren't reachable.
func skipIfNotReady(t *testing.T) {
	t.Helper()

	// Check Vault.
	client := vaultClient(t)
	_, err := client.Sys().Health()
	if err != nil {
		t.Skipf("Vault not reachable: %v", err)
	}

	// Check PingFederate. PF 13 requires auth and X-XSRF-Header for admin API.
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // integration test against local self-signed cert
		},
	}
	req, err := http.NewRequest(http.MethodGet, pfAdminURL+"/pf-admin-api/v1/version", nil)
	if err != nil {
		t.Skipf("PingFederate request creation failed: %v", err)
	}
	req.SetBasicAuth(pfAdminUser, pfAdminPassword)
	req.Header.Set("X-XSRF-Header", "PingFederate")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Skipf("PingFederate not reachable: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("PingFederate not ready (status %d)", resp.StatusCode)
	}
}

// readJWKSRaw performs a raw HTTP GET to the JWKS endpoint (no Vault token).
// Returns the status code and the JWKS data. If Vault wraps the response in its
// standard envelope (with a "data" field), the inner data is extracted.
func readJWKSRaw(t *testing.T, connName string) (int, map[string]any) {
	t.Helper()

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}

	resp, err := http.Get(addr + "/v1/" + pluginPath + "/jwks/" + connName) //nolint:gosec // test helper with hardcoded local URL
	if err != nil {
		t.Fatalf("failed to GET JWKS: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read JWKS response: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to parse JWKS response: %v", err)
	}

	// If Vault returned its standard envelope, extract the inner data.
	if data, ok := result["data"].(map[string]any); ok {
		return resp.StatusCode, data
	}

	return resp.StatusCode, result
}

// pushJWKSToPF reads the JWKS from Vault for the given connection and updates the
// PF OAuth client with inline JWKS. This is needed because the PF container
// cannot reach Vault's JWKS endpoint on the host network.
func pushJWKSToPF(t *testing.T, vaultClient *api.Client, connName, pfClientID string) {
	t.Helper()

	// Read JWKS from Vault.
	_, jwksData := readJWKSRaw(t, connName)
	jwksJSON, err := json.Marshal(jwksData)
	if err != nil {
		t.Fatalf("failed to marshal JWKS: %v", err)
	}

	// Build the PF client update payload with inline JWKS.
	pfClient := map[string]any{
		"clientId": pfClientID,
		"name":     "Vault Foothold (JWT)",
		"clientAuth": map[string]any{
			"type":                    "PRIVATE_KEY_JWT",
			"enforceReplayPrevention": false,
		},
		"jwksSettings": map[string]any{
			"jwks": string(jwksJSON),
		},
		"grantTypes":                 []string{"CLIENT_CREDENTIALS"},
		"defaultAccessTokenManagerRef": map[string]any{"id": "jwtatm"},
	}
	payload, err := json.Marshal(pfClient)
	if err != nil {
		t.Fatalf("failed to marshal PF client payload: %v", err)
	}

	// Update the PF client via admin API.
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // integration test
		},
	}
	req, err := http.NewRequest(http.MethodPut,
		pfAdminURL+"/pf-admin-api/v1/oauth/clients/"+pfClientID,
		bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("failed to create PF client update request: %v", err)
	}
	req.SetBasicAuth(pfAdminUser, pfAdminPassword)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-XSRF-Header", "PingFederate")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("failed to update PF client JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PF client update failed (HTTP %d): %s", resp.StatusCode, string(body))
	}
}

// requireField asserts a field exists in the secret data and returns its string value.
func requireField(t *testing.T, data map[string]any, field string) string {
	t.Helper()

	val, ok := data[field]
	if !ok {
		t.Fatalf("expected field %q in response, got keys: %v", field, keys(data))
	}

	str, ok := val.(string)
	if !ok {
		return fmt.Sprintf("%v", val)
	}
	return str
}

func keys(m map[string]any) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}
