package pingfederate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// mockPingFederateClient implements PingFederateClient for testing.
type mockPingFederateClient struct {
	updateClientSecretFunc func(ctx context.Context, clientID string) (string, error)
	getAccessTokenFunc     func(ctx context.Context, clientID, clientSecret string) (*AccessTokenResponse, error)
}

func (m *mockPingFederateClient) UpdateClientSecret(ctx context.Context, clientID string) (string, error) {
	if m.updateClientSecretFunc != nil {
		return m.updateClientSecretFunc(ctx, clientID)
	}
	return "new-mock-secret", nil
}

func (m *mockPingFederateClient) GetAccessToken(ctx context.Context, clientID, clientSecret string) (*AccessTokenResponse, error) {
	if m.getAccessTokenFunc != nil {
		return m.getAccessTokenFunc(ctx, clientID, clientSecret)
	}
	return &AccessTokenResponse{
		AccessToken: "mock-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func (m *mockPingFederateClient) HTTPClient() *http.Client {
	return &http.Client{}
}

// newTestBackend creates a configured backend for testing.
func newTestBackend(t *testing.T) (*pingFederateBackend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b := backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatalf("unable to setup backend: %v", err)
	}

	return b, config.StorageView
}

func writeTestConfig(t *testing.T, b logical.Backend, storage logical.Storage) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"client_id":         "admin-client",
			"client_secret":     "admin-secret",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response writing config: %v", resp.Error())
	}
}

func writeTestRole(t *testing.T, b logical.Backend, storage logical.Storage) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]any{
			"connection_name": "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing role: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response writing role: %v", resp.Error())
	}
}

// --- Backend Factory Tests ---

func TestBackendFactory(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	if b == nil {
		t.Fatal("expected backend, got nil")
	}
	if b.Type() != logical.TypeLogical {
		t.Fatalf("expected TypeLogical, got %v", b.Type())
	}
}

// --- Config Tests ---

func TestConfigReadEmpty(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response for unconfigured backend, got %v", resp)
	}
}

func TestConfigWriteMissingFields(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data:      map[string]any{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing required fields")
	}
}

func TestConfigWriteMissingTokenURL(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "my-client-id",
			"client_secret": "my-client-secret",
			"url":           "https://pingfederate.example.com:9999",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing token_url")
	}
}

func TestConfigWriteAndRead(t *testing.T) {
	b, storage := newTestBackend(t)

	// Write config.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"client_id":         "my-client-id",
			"client_secret":     "my-client-secret",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Read config back.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Data["client_id"] != "my-client-id" {
		t.Fatalf("expected client_id 'my-client-id', got %v", resp.Data["client_id"])
	}
	if resp.Data["url"] != "https://pingfederate.example.com:9999" {
		t.Fatalf("expected url 'https://pingfederate.example.com:9999', got %v", resp.Data["url"])
	}
	if resp.Data["token_url"] != "https://pingfederate.example.com:9031/as/token.oauth2" {
		t.Fatalf("expected token_url, got %v", resp.Data["token_url"])
	}
	if _, exists := resp.Data["client_secret"]; exists {
		t.Fatal("client_secret should not be returned in read response")
	}
}

func TestConfigUpdate(t *testing.T) {
	b, storage := newTestBackend(t)

	// Create initial config.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"client_id":         "my-client-id",
			"client_secret":     "my-client-secret",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Update only the URL.
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"url":               "https://pingfederate-new.example.com:9999",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the update preserved existing fields.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Data["client_id"] != "my-client-id" {
		t.Fatalf("expected client_id 'my-client-id', got %v", resp.Data["client_id"])
	}
	if resp.Data["url"] != "https://pingfederate-new.example.com:9999" {
		t.Fatalf("expected updated url, got %v", resp.Data["url"])
	}
}

func TestConfigDelete(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	// Delete config.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify it's gone.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response after delete, got %v", resp)
	}
}

func TestConfigList(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	// Write a second connection.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/other",
		Storage:   storage,
		Data: map[string]any{
			"client_id":         "other-client",
			"client_secret":     "other-secret",
			"url":               "https://other.example.com:9999",
			"token_url":         "https://other.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// List connections.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "config/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	keys, ok := resp.Data["keys"].([]string)
	if !ok {
		t.Fatalf("expected keys to be []string, got %T", resp.Data["keys"])
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 connections, got %d: %v", len(keys), keys)
	}
}

func TestConfigDeleteClearsClientCache(t *testing.T) {
	b, storage := newTestBackend(t)

	b.clients["test"] = &mockPingFederateClient{}

	writeTestConfig(t, b, storage)

	// Delete config.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify client was removed from cache.
	b.lock.RLock()
	_, exists := b.clients["test"]
	b.lock.RUnlock()
	if exists {
		t.Fatal("expected client cache entry to be cleared after config delete")
	}
}

// --- Role Tests ---

func TestRoleCRUD(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	// Create role.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/my-role",
		Storage:   storage,
		Data: map[string]any{
			"connection_name":       "test",
			"default_scope":         "openid",
			"allowed_scopes":        "openid,email,profile",
			"allowed_metadata_keys": "team,env",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Read role.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/my-role",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Data["name"] != "my-role" {
		t.Fatalf("expected name 'my-role', got %v", resp.Data["name"])
	}
	if resp.Data["connection_name"] != "test" {
		t.Fatalf("expected connection_name 'test', got %v", resp.Data["connection_name"])
	}
	if resp.Data["default_scope"] != "openid" {
		t.Fatalf("expected default_scope 'openid', got %v", resp.Data["default_scope"])
	}
	allowedScopes, ok := resp.Data["allowed_scopes"].([]string)
	if !ok {
		t.Fatalf("expected allowed_scopes to be []string, got %T", resp.Data["allowed_scopes"])
	}
	if len(allowedScopes) != 3 {
		t.Fatalf("expected 3 allowed_scopes, got %d: %v", len(allowedScopes), allowedScopes)
	}
	allowedKeys, ok := resp.Data["allowed_metadata_keys"].([]string)
	if !ok {
		t.Fatalf("expected allowed_metadata_keys to be []string, got %T", resp.Data["allowed_metadata_keys"])
	}
	if len(allowedKeys) != 2 {
		t.Fatalf("expected 2 allowed_metadata_keys, got %d: %v", len(allowedKeys), allowedKeys)
	}

	// List roles.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	keys, ok := resp.Data["keys"].([]string)
	if !ok || len(keys) != 1 || keys[0] != "my-role" {
		t.Fatalf("expected [my-role], got %v", resp.Data["keys"])
	}

	// Delete role.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/my-role",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify it's gone.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/my-role",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response after delete, got %v", resp)
	}
}

func TestRoleWriteMissingConnectionName(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data:      map[string]any{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing connection_name")
	}
}

func TestRoleWriteNonexistentConnection(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]any{
			"connection_name": "nonexistent",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for nonexistent connection")
	}
}

func TestRoleWriteDefaultScopeNotInAllowedScopes(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad-scope-role",
		Storage:   storage,
		Data: map[string]any{
			"connection_name": "test",
			"default_scope":   "openid profile",
			"allowed_scopes":  "openid,email",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when default_scope contains values not in allowed_scopes")
	}
	if !strings.Contains(resp.Error().Error(), "profile") {
		t.Fatalf("expected error to mention 'profile', got: %s", resp.Error())
	}
}

func TestRoleWriteDefaultScopeWithinAllowedScopes(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/good-scope-role",
		Storage:   storage,
		Data: map[string]any{
			"connection_name": "test",
			"default_scope":   "openid email",
			"allowed_scopes":  "openid,email,profile",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify values were stored.
	readResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/good-scope-role",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error reading role: %v", err)
	}
	if readResp.Data["default_scope"] != "openid email" {
		t.Fatalf("expected default_scope='openid email', got %v", readResp.Data["default_scope"])
	}
	allowedScopes, ok := readResp.Data["allowed_scopes"].([]string)
	if !ok {
		t.Fatalf("expected allowed_scopes to be []string, got %T", readResp.Data["allowed_scopes"])
	}
	if len(allowedScopes) != 3 {
		t.Fatalf("expected 3 allowed_scopes, got %d: %v", len(allowedScopes), allowedScopes)
	}
}

func TestRoleAllowedMetadataKeysRoundTrip(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/meta-role",
		Storage:   storage,
		Data: map[string]any{
			"connection_name":       "test",
			"allowed_metadata_keys": "team,env,department",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing role: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	readResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/meta-role",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error reading role: %v", err)
	}
	if readResp == nil {
		t.Fatal("expected role response, got nil")
	}

	allowedKeys, ok := readResp.Data["allowed_metadata_keys"].([]string)
	if !ok {
		t.Fatalf("expected allowed_metadata_keys to be []string, got %T", readResp.Data["allowed_metadata_keys"])
	}
	if len(allowedKeys) != 3 {
		t.Fatalf("expected 3 allowed_metadata_keys, got %d: %v", len(allowedKeys), allowedKeys)
	}
	expected := map[string]bool{"team": true, "env": true, "department": true}
	for _, k := range allowedKeys {
		if !expected[k] {
			t.Errorf("unexpected allowed_metadata_key: %q", k)
		}
	}
}

func TestRoleAllowedMetadataKeysNotReturnedWhenEmpty(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)
	writeTestRole(t, b, storage)

	readResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/test-role",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error reading role: %v", err)
	}
	if readResp == nil {
		t.Fatal("expected role response, got nil")
	}
	if _, exists := readResp.Data["allowed_metadata_keys"]; exists {
		t.Fatal("expected allowed_metadata_keys to be absent when not configured")
	}
}

// --- Static Role Tests ---

func TestStaticRoleReadConfigEmpty(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-roles/test-role",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response for nonexistent role, got %v", resp)
	}
}

func TestStaticRoleReadConfigReturnsConfig(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	// Write a role.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
			"connection_name": "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read should return role config, NOT credentials.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Data["name"] != "terraform" {
		t.Fatalf("expected name 'terraform', got %v", resp.Data["name"])
	}
	if resp.Data["client_id"] != "terraform-client" {
		t.Fatalf("expected client_id 'terraform-client', got %v", resp.Data["client_id"])
	}
	if resp.Data["connection_name"] != "test" {
		t.Fatalf("expected connection_name 'test', got %v", resp.Data["connection_name"])
	}
	// Should NOT contain credential data.
	if _, exists := resp.Data["access_token"]; exists {
		t.Fatal("static-roles read should not return access_token; use static-creds instead")
	}
}

func TestStaticCredsReadEmpty(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/test-role",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response for nonexistent role, got %v", resp)
	}
}

func TestStaticRoleWriteAndList(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	// Write a role.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
			"connection_name": "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// List roles.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "static-roles/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	keys, ok := resp.Data["keys"].([]string)
	if !ok || len(keys) != 1 || keys[0] != "terraform" {
		t.Fatalf("expected [terraform], got %v", resp.Data["keys"])
	}
}

func TestStaticRoleWriteMissingClientID(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":            "test-role",
			"connection_name": "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing client_id")
	}
}

func TestStaticRoleWriteMissingConnectionName(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name":      "test-role",
			"client_id": "terraform-client",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing connection_name")
	}
}

func TestStaticRoleDelete(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	// Create a role.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
			"connection_name": "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Delete it.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify it's gone via list.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "static-roles/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		if keys, ok := resp.Data["keys"].([]string); ok && len(keys) > 0 {
			t.Fatalf("expected empty list after delete, got %v", keys)
		}
	}
}

// --- Credential Generation Tests (static-creds) ---

func TestStaticCredsReadGeneratesToken(t *testing.T) {
	b, storage := newTestBackend(t)

	// Inject mock client.
	b.clients["test"] = &mockPingFederateClient{}

	writeTestConfig(t, b, storage)

	// Create a role.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
			"connection_name": "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read creds — should return a bearer token.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/terraform",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response with access token, got nil")
	}
	if resp.Data["access_token"] != "mock-access-token" {
		t.Fatalf("expected 'mock-access-token', got %v", resp.Data["access_token"])
	}
	if resp.Data["token_type"] != "Bearer" {
		t.Fatalf("expected 'Bearer', got %v", resp.Data["token_type"])
	}
	if resp.Data["expires_in"] != 3600 {
		t.Fatalf("expected 3600, got %v", resp.Data["expires_in"])
	}
}

func TestStaticCredsReadWithoutConfig(t *testing.T) {
	b, storage := newTestBackend(t)

	// Write a role without configuring the backend.
	entry, err := logical.StorageEntryJSON("static-roles/terraform", &staticRoleEntry{
		Name:           "terraform",
		ClientID:       "terraform-client",
		ConnectionName: "test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read creds should fail because backend is not configured.
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/terraform",
		Storage:   storage,
	})
	if err == nil {
		t.Fatal("expected error when reading creds without backend config")
	}
}

func TestStaticCredsReadClientError(t *testing.T) {
	b, storage := newTestBackend(t)

	b.clients["test"] = &mockPingFederateClient{
		updateClientSecretFunc: func(_ context.Context, _ string) (string, error) {
			return "", fmt.Errorf("PingFederate unavailable")
		},
	}

	writeTestConfig(t, b, storage)

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
			"connection_name": "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/terraform",
		Storage:   storage,
	})
	if err == nil {
		t.Fatal("expected error when PingFederate client fails")
	}
}

// --- Rotate Root Tests ---

func TestRotateRoot(t *testing.T) {
	b, storage := newTestBackend(t)

	b.clients["test"] = &mockPingFederateClient{
		updateClientSecretFunc: func(_ context.Context, clientID string) (string, error) {
			if clientID != "admin-client" {
				t.Fatalf("expected rotation of admin-client, got %s", clientID)
			}
			return "rotated-admin-secret", nil
		},
	}

	writeTestConfig(t, b, storage)

	// Rotate root.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response with warning, got nil")
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("expected warning about rotated credentials")
	}

	// Verify config was updated.
	cfg, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("unexpected error reading config: %v", err)
	}
	if cfg.ClientSecret != "rotated-admin-secret" {
		t.Fatalf("expected rotated secret, got %q", cfg.ClientSecret)
	}
}

func TestRotateRootWithoutConfig(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when config is missing")
	}
}

func TestRotateRootPingFederateError(t *testing.T) {
	b, storage := newTestBackend(t)

	b.clients["test"] = &mockPingFederateClient{
		updateClientSecretFunc: func(_ context.Context, _ string) (string, error) {
			return "", fmt.Errorf("PingFederate error")
		},
	}

	writeTestConfig(t, b, storage)

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root/test",
		Storage:   storage,
	})
	if err == nil {
		t.Fatal("expected error when PingFederate rotation fails")
	}
}

// --- JWT Config Tests ---

func testRSAPrivateKeyPEM(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func testECPrivateKeyPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func writeTestJWTConfig(t *testing.T, b logical.Backend, storage logical.Storage) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwt-admin-client",
			"private_key":       testRSAPrivateKeyPEM(t),
			"private_key_id":    "key-1",
			"signing_algorithm": "RS256",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing JWT config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response writing JWT config: %v", resp.Error())
	}
}

func TestConfigWriteJWT(t *testing.T) {
	b, storage := newTestBackend(t)
	writeTestJWTConfig(t, b, storage)

	_ = b
	_ = storage
}

func TestConfigWriteJWTDefaultAlgorithm(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwt-admin-client",
			"private_key":       testRSAPrivateKeyPEM(t),
			"private_key_id":    "key-1",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify default signing algorithm was set.
	cfg, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SigningAlgorithm != "RS256" {
		t.Fatalf("expected default signing_algorithm RS256, got %q", cfg.SigningAlgorithm)
	}
}

func TestConfigWriteJWTAutoGenerateKey(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwt-admin-client",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify the stored config has an internally generated key.
	cfg, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	if cfg.PrivateKey == "" {
		t.Fatal("expected auto-generated private_key")
	}
	if cfg.PrivateKeyID == "" {
		t.Fatal("expected auto-generated private_key_id")
	}
	if cfg.KeySource != "internal" {
		t.Fatalf("expected key_source=internal, got %q", cfg.KeySource)
	}
	if cfg.SigningAlgorithm != "RS256" {
		t.Fatalf("expected default signing_algorithm=RS256, got %q", cfg.SigningAlgorithm)
	}
	// Verify the generated key is valid.
	if _, err := parsePrivateKey(cfg.PrivateKey); err != nil {
		t.Fatalf("generated key is not valid: %v", err)
	}
}

func TestConfigWriteJWTAutoGenerateKeyID(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwt-admin-client",
			"private_key":       testRSAPrivateKeyPEM(t),
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	cfg, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	if cfg.PrivateKeyID == "" {
		t.Fatal("expected auto-generated private_key_id")
	}
	if cfg.KeySource != "external" {
		t.Fatalf("expected key_source=external for user-provided key, got %q", cfg.KeySource)
	}
}

func TestConfigWriteJWTInvalidAlgorithm(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwt-admin-client",
			"private_key":       testRSAPrivateKeyPEM(t),
			"private_key_id":    "key-1",
			"signing_algorithm": "INVALID",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for invalid signing_algorithm")
	}
}

func TestConfigWriteJWTKeyAlgorithmMismatch(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwt-admin-client",
			"private_key":       testECPrivateKeyPEM(t),
			"private_key_id":    "key-1",
			"signing_algorithm": "RS256",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for EC key with RS256")
	}
}

func TestConfigWriteJWTInvalidKey(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":    "private_key_jwt",
			"client_id":      "jwt-admin-client",
			"private_key":    "not-a-valid-pem",
			"private_key_id": "key-1",
			"url":            "https://pingfederate.example.com:9999",
			"token_url":      "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for invalid PEM key")
	}
}

func TestConfigWriteInvalidAuthMethod(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":   "invalid_method",
			"client_id":     "admin-client",
			"client_secret": "admin-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for invalid auth_method")
	}
}

func TestConfigSwitchAuthMethodClearsStaleFields(t *testing.T) {
	b, storage := newTestBackend(t)

	// Start with client_secret auth.
	writeTestConfig(t, b, storage)

	// Switch to private_key_jwt.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"private_key":       testRSAPrivateKeyPEM(t),
			"private_key_id":    "key-1",
			"signing_algorithm": "RS256",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify client_secret was cleared from storage.
	cfg, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientSecret != "" {
		t.Fatal("expected client_secret to be cleared after switching to private_key_jwt")
	}
	if cfg.PrivateKey == "" {
		t.Fatal("expected private_key to be set")
	}

	// Switch back to client_secret.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "client_secret",
			"client_secret":     "new-secret",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify JWT fields were cleared from storage.
	cfg, err = getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PrivateKey != "" {
		t.Fatal("expected private_key to be cleared after switching to client_secret")
	}
	if cfg.PrivateKeyID != "" {
		t.Fatal("expected private_key_id to be cleared after switching to client_secret")
	}
	if cfg.SigningAlgorithm != "" {
		t.Fatal("expected signing_algorithm to be cleared after switching to client_secret")
	}
	if cfg.KeySource != "" {
		t.Fatal("expected key_source to be cleared after switching to client_secret")
	}
	if cfg.ClientSecret != "new-secret" {
		t.Fatalf("expected client_secret 'new-secret', got %q", cfg.ClientSecret)
	}
}

func TestConfigReadJWT(t *testing.T) {
	b, storage := newTestBackend(t)
	writeTestJWTConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Data["auth_method"] != "private_key_jwt" {
		t.Fatalf("expected auth_method 'private_key_jwt', got %v", resp.Data["auth_method"])
	}
	if resp.Data["signing_algorithm"] != "RS256" {
		t.Fatalf("expected signing_algorithm 'RS256', got %v", resp.Data["signing_algorithm"])
	}
	if resp.Data["private_key_id"] != "key-1" {
		t.Fatalf("expected private_key_id 'key-1', got %v", resp.Data["private_key_id"])
	}
	if _, exists := resp.Data["private_key"]; exists {
		t.Fatal("private_key should not be returned in read response")
	}
	if resp.Data["key_source"] != "external" {
		t.Fatalf("expected key_source 'external', got %v", resp.Data["key_source"])
	}
}

func TestConfigReadClientSecretDefaultAuthMethod(t *testing.T) {
	b, storage := newTestBackend(t)
	writeTestConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Data["auth_method"] != "client_secret" {
		t.Fatalf("expected auth_method 'client_secret', got %v", resp.Data["auth_method"])
	}
}

func TestRotateRootJWTGeneratesNewKey(t *testing.T) {
	b, storage := newTestBackend(t)
	writeTestJWTConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected success, got error: %v", resp)
	}

	kid, ok := resp.Data["private_key_id"].(string)
	if !ok || kid == "" {
		t.Fatal("expected private_key_id in response")
	}
	if resp.Data["signing_algorithm"] != "RS256" {
		t.Fatalf("expected signing_algorithm=RS256, got %v", resp.Data["signing_algorithm"])
	}
	if resp.Data["key_source"] != "internal" {
		t.Fatalf("expected key_source=internal, got %v", resp.Data["key_source"])
	}

	// Verify the stored config has the new key.
	cfg, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	if cfg.PrivateKeyID != kid {
		t.Fatalf("stored kid %q does not match response kid %q", cfg.PrivateKeyID, kid)
	}
	if cfg.KeySource != "internal" {
		t.Fatalf("expected stored key_source=internal, got %q", cfg.KeySource)
	}
	// Verify the new key is valid.
	if _, err := parsePrivateKey(cfg.PrivateKey); err != nil {
		t.Fatalf("stored key is not valid: %v", err)
	}
}

func TestStaticCredsReadGeneratesTokenJWT(t *testing.T) {
	b, storage := newTestBackend(t)

	// Inject mock client (same interface, independent of auth method).
	b.clients["test"] = &mockPingFederateClient{}

	writeTestJWTConfig(t, b, storage)

	// Create a role.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
			"connection_name": "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read creds — should return a bearer token.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/terraform",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response with access token, got nil")
	}
	if resp.Data["access_token"] != "mock-access-token" {
		t.Fatalf("expected 'mock-access-token', got %v", resp.Data["access_token"])
	}
}

// --- Rotation Period Tests ---

func TestStaticRoleWriteWithRotationPeriod(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
			"connection_name": "test",
			"rotation_period": 3600,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Read back config and verify rotation_period is set.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Data["rotation_period"] != int64(3600) {
		t.Fatalf("expected rotation_period 3600, got %v", resp.Data["rotation_period"])
	}
	if resp.Data["last_rotated"] == nil {
		t.Fatal("expected last_rotated to be set")
	}
}

func TestStaticRoleWriteRotationPeriodTooShort(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
			"connection_name": "test",
			"rotation_period": 30,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for rotation_period < 60s")
	}
}

func TestPeriodicFuncRotatesWhenDue(t *testing.T) {
	b, storage := newTestBackend(t)

	rotated := false
	b.clients["test"] = &mockPingFederateClient{
		updateClientSecretFunc: func(_ context.Context, clientID string) (string, error) {
			if clientID != "terraform-client" {
				t.Fatalf("expected rotation of terraform-client, got %s", clientID)
			}
			rotated = true
			return "new-secret", nil
		},
	}

	writeTestConfig(t, b, storage)

	// Write a role with rotation_period, but set last_rotated far in the past.
	role := &staticRoleEntry{
		Name:           "terraform",
		ClientID:       "terraform-client",
		ConnectionName: "test",
		RotationPeriod: 60 * time.Second,
		LastRotated:    time.Now().Add(-2 * time.Hour),
	}
	entry, err := logical.StorageEntryJSON("static-roles/terraform", role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Call periodic function.
	err = b.periodicFunc(context.Background(), &logical.Request{Storage: storage})
	if err != nil {
		t.Fatalf("periodicFunc returned error: %v", err)
	}

	if !rotated {
		t.Fatal("expected rotation to occur")
	}

	// Verify last_rotated was updated.
	updatedRole, err := getStaticRole(context.Background(), storage, "terraform")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if time.Since(updatedRole.LastRotated) > 5*time.Second {
		t.Fatalf("expected last_rotated to be recent, got %v", updatedRole.LastRotated)
	}
}

func TestPeriodicFuncSkipsWhenNotDue(t *testing.T) {
	b, storage := newTestBackend(t)

	rotated := false
	b.clients["test"] = &mockPingFederateClient{
		updateClientSecretFunc: func(_ context.Context, _ string) (string, error) {
			rotated = true
			return "new-secret", nil
		},
	}

	writeTestConfig(t, b, storage)

	// Write a role with rotation_period and last_rotated = now (not due yet).
	role := &staticRoleEntry{
		Name:           "terraform",
		ClientID:       "terraform-client",
		ConnectionName: "test",
		RotationPeriod: 3600 * time.Second,
		LastRotated:    time.Now(),
	}
	entry, err := logical.StorageEntryJSON("static-roles/terraform", role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = b.periodicFunc(context.Background(), &logical.Request{Storage: storage})
	if err != nil {
		t.Fatalf("periodicFunc returned error: %v", err)
	}

	if rotated {
		t.Fatal("expected no rotation since period has not elapsed")
	}
}

func TestPeriodicFuncSkipsWithoutRotationPeriod(t *testing.T) {
	b, storage := newTestBackend(t)

	rotated := false
	b.clients["test"] = &mockPingFederateClient{
		updateClientSecretFunc: func(_ context.Context, _ string) (string, error) {
			rotated = true
			return "new-secret", nil
		},
	}

	writeTestConfig(t, b, storage)

	// Write a role without rotation_period.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
			"connection_name": "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = b.periodicFunc(context.Background(), &logical.Request{Storage: storage})
	if err != nil {
		t.Fatalf("periodicFunc returned error: %v", err)
	}

	if rotated {
		t.Fatal("expected no rotation for role without rotation_period")
	}
}

// --- JWKS Tests ---

func TestJWKSNotConfigured(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	keys, ok := resp.Data["keys"].([]any)
	if !ok {
		t.Fatalf("expected keys to be []any, got %T", resp.Data["keys"])
	}
	if len(keys) != 0 {
		t.Fatalf("expected empty keys array, got %d keys", len(keys))
	}
}

func TestJWKSClientSecretAuth(t *testing.T) {
	b, storage := newTestBackend(t)
	writeTestConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	keys, ok := resp.Data["keys"].([]any)
	if !ok {
		t.Fatalf("expected keys to be []any, got %T", resp.Data["keys"])
	}
	if len(keys) != 0 {
		t.Fatalf("expected empty keys for client_secret auth, got %d keys", len(keys))
	}
}

func TestJWKSPrivateKeyJWTRSA(t *testing.T) {
	b, storage := newTestBackend(t)
	writeTestJWTConfig(t, b, storage)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	keys, ok := resp.Data["keys"].([]any)
	if !ok {
		t.Fatalf("expected keys to be []any, got %T", resp.Data["keys"])
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	key, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("expected key to be map[string]any, got %T", keys[0])
	}
	if key["kty"] != "RSA" {
		t.Fatalf("expected kty RSA, got %v", key["kty"])
	}
	if key["kid"] != "key-1" {
		t.Fatalf("expected kid key-1, got %v", key["kid"])
	}
	if key["alg"] != "RS256" {
		t.Fatalf("expected alg RS256, got %v", key["alg"])
	}
	if key["use"] != "sig" {
		t.Fatalf("expected use sig, got %v", key["use"])
	}

	if resp.Data[logical.HTTPContentType] != "application/json" {
		t.Fatalf("expected application/json content type, got %v", resp.Data[logical.HTTPContentType])
	}
	rawBody, ok := resp.Data[logical.HTTPRawBody].(string)
	if !ok {
		t.Fatalf("expected http_raw_body to be string, got %T", resp.Data[logical.HTTPRawBody])
	}
	if len(rawBody) == 0 {
		t.Fatal("expected non-empty raw body")
	}
}

func TestJWKSPrivateKeyJWTEC(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwt-admin-client",
			"private_key":       testECPrivateKeyPEM(t),
			"private_key_id":    "ec-key-1",
			"signing_algorithm": "ES256",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	keys, ok := resp.Data["keys"].([]any)
	if !ok {
		t.Fatalf("expected keys to be []any, got %T", resp.Data["keys"])
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	key, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("expected key to be map[string]any, got %T", keys[0])
	}
	if key["kty"] != "EC" {
		t.Fatalf("expected kty EC, got %v", key["kty"])
	}
	if key["kid"] != "ec-key-1" {
		t.Fatalf("expected kid ec-key-1, got %v", key["kid"])
	}
	if key["alg"] != "ES256" {
		t.Fatalf("expected alg ES256, got %v", key["alg"])
	}
}

// --- Creds (Token Brokering) Tests ---

func newTestBackendWithEntity(t *testing.T, entityID string, metadata map[string]string) (*pingFederateBackend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	sysView, ok := config.System.(*logical.StaticSystemView)
	if !ok {
		t.Fatal("expected StaticSystemView from TestBackendConfig")
	}
	sysView.EntityVal = &logical.Entity{
		ID:       entityID,
		Name:     "test-entity",
		Metadata: metadata,
	}

	b := backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatalf("unable to setup backend: %v", err)
	}

	return b, config.StorageView
}

func newMockTokenServer(t *testing.T, validate func(r *http.Request)) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if validate != nil {
			validate(r)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(AccessTokenResponse{
			AccessToken: "brokered-jwt-token",
			TokenType:   "Bearer",
			ExpiresIn:   7200,
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
}

// writeCredsPrereqs writes a config at config/test and a role at roles/test-role
// with the given role data merged into the base role fields.
func writeCredsPrereqs(t *testing.T, b logical.Backend, storage logical.Storage, configData map[string]any, roleData map[string]any) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data:      configData,
	})
	if err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response writing config: %v", resp.Error())
	}

	rd := map[string]any{
		"connection_name": "test",
	}
	for k, v := range roleData {
		rd[k] = v
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data:      rd,
	})
	if err != nil {
		t.Fatalf("unexpected error writing role: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response writing role: %v", resp.Error())
	}
}

func TestCredsReadWithoutConfig(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-123", nil)

	// Write a role directly to storage without a config.
	entry, err := logical.StorageEntryJSON("roles/test-role", &roleEntry{
		Name:           "test-role",
		ConnectionName: "test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for unconfigured connection")
	}
}

func TestCredsReadNonexistentRole(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-123", nil)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/nonexistent",
		Storage:   storage,
		EntityID:  "entity-123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for nonexistent role")
	}
}

func TestCredsReadWithoutEntityID(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-123", nil)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing entity ID")
	}
}

func TestCredsReadBasicAuth(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-abc-123", map[string]string{
		"team": "platform",
		"env":  "prod",
	})

	server := newMockTokenServer(t, func(r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin-client" || pass != "admin-secret" {
			t.Fatalf("expected Basic Auth admin-client:admin-secret, got %s:%s (ok=%v)", user, pass, ok)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("vault_entity_id") != "entity-abc-123" {
			t.Fatalf("expected vault_entity_id=entity-abc-123, got %q", r.FormValue("vault_entity_id"))
		}
		if r.FormValue("team") != "platform" {
			t.Fatalf("expected team=platform, got %q", r.FormValue("team"))
		}
		if r.FormValue("env") != "prod" {
			t.Fatalf("expected env=prod, got %q", r.FormValue("env"))
		}
	})
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"client_id":         "admin-client",
		"client_secret":     "admin-secret",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, nil)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-abc-123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
	if resp.Data["access_token"] != "brokered-jwt-token" {
		t.Fatalf("expected access_token=brokered-jwt-token, got %v", resp.Data["access_token"])
	}
	if resp.Data["token_type"] != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %v", resp.Data["token_type"])
	}
}

func TestCredsReadJWTAuth(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-jwt-789", map[string]string{
		"app": "my-service",
	})

	server := newMockTokenServer(t, func(r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			t.Fatal("expected no Basic Auth for private_key_jwt")
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			t.Fatalf("unexpected client_assertion_type: %q", r.FormValue("client_assertion_type"))
		}
		if r.FormValue("client_assertion") == "" {
			t.Fatal("expected non-empty client_assertion")
		}
		if r.FormValue("client_id") != "jwt-admin-client" {
			t.Fatalf("expected client_id=jwt-admin-client, got %q", r.FormValue("client_id"))
		}
		if r.FormValue("vault_entity_id") != "entity-jwt-789" {
			t.Fatalf("expected vault_entity_id=entity-jwt-789, got %q", r.FormValue("vault_entity_id"))
		}
		if r.FormValue("app") != "my-service" {
			t.Fatalf("expected app=my-service, got %q", r.FormValue("app"))
		}
	})
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"auth_method":       "private_key_jwt",
		"client_id":         "jwt-admin-client",
		"private_key":       testRSAPrivateKeyPEM(t),
		"private_key_id":    "key-1",
		"signing_algorithm": "RS256",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, nil)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-jwt-789",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
	if resp.Data["access_token"] != "brokered-jwt-token" {
		t.Fatalf("expected access_token=brokered-jwt-token, got %v", resp.Data["access_token"])
	}
}

func TestCredsWriteWithScope(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-scope-1", nil)

	server := newMockTokenServer(t, func(r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("scope") != "openid profile" {
			t.Fatalf("expected scope='openid profile', got %q", r.FormValue("scope"))
		}
	})
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"client_id":         "admin-client",
		"client_secret":     "admin-secret",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, nil)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-scope-1",
		Data: map[string]any{
			"scope": "openid profile",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
	if resp.Data["access_token"] != "brokered-jwt-token" {
		t.Fatalf("expected access_token=brokered-jwt-token, got %v", resp.Data["access_token"])
	}
}

func TestCredsReadReservedMetadataKeysWarning(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-reserved-1", map[string]string{
		"grant_type": "authorization_code",
		"client_id":  "evil-client",
		"team":       "platform",
	})

	server := newMockTokenServer(t, func(r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		// Reserved keys must not be overwritten.
		if r.FormValue("grant_type") != "client_credentials" {
			t.Fatalf("grant_type was overwritten: got %q", r.FormValue("grant_type"))
		}
		// Safe key should pass through.
		if r.FormValue("team") != "platform" {
			t.Fatalf("expected team=platform, got %q", r.FormValue("team"))
		}
	})
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"client_id":         "admin-client",
		"client_secret":     "admin-secret",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, nil)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-reserved-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
	if resp.Data["access_token"] != "brokered-jwt-token" {
		t.Fatalf("expected access_token=brokered-jwt-token, got %v", resp.Data["access_token"])
	}

	// Verify warnings were emitted for the reserved keys.
	reservedWarnings := 0
	for _, w := range resp.Warnings {
		if strings.Contains(w, "conflicts with a reserved OAuth parameter") {
			reservedWarnings++
		}
	}
	if reservedWarnings != 2 {
		t.Errorf("expected 2 reserved key warnings, got %d; warnings: %v", reservedWarnings, resp.Warnings)
	}
}

// --- Internal Key Generation Tests ---

func TestConfigWriteAutoGenerateEC(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "ec-client",
			"signing_algorithm": "ES256",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	cfg, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	if cfg.SigningAlgorithm != "ES256" {
		t.Fatalf("expected signing_algorithm=ES256, got %q", cfg.SigningAlgorithm)
	}
	if cfg.KeySource != "internal" {
		t.Fatalf("expected key_source=internal, got %q", cfg.KeySource)
	}
	key, err := parsePrivateKey(cfg.PrivateKey)
	if err != nil {
		t.Fatalf("generated key is not valid: %v", err)
	}
	if err := validateKeyAlgorithmMatch(key, "ES256"); err != nil {
		t.Fatalf("generated key does not match algorithm: %v", err)
	}
}

func TestConfigReadKeySource(t *testing.T) {
	b, storage := newTestBackend(t)

	// Write config with auto-generated key.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "auto-client",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Read and verify key_source is surfaced.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Data["key_source"] != "internal" {
		t.Fatalf("expected key_source=internal, got %v", resp.Data["key_source"])
	}
}

func TestJWKSAfterAutoGenerate(t *testing.T) {
	b, storage := newTestBackend(t)

	// Write config with auto-generated key.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwks-client",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Read JWKS — should have a key.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected JWKS response")
	}

	keys, ok := resp.Data["keys"].([]any)
	if !ok {
		t.Fatalf("expected keys array, got %T", resp.Data["keys"])
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

func TestRotateRootPrivateKeyJWTKeyChanges(t *testing.T) {
	b, storage := newTestBackend(t)

	// Write config with auto-generated key.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "rotate-client",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Capture the original key and kid.
	cfg1, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	originalKey := cfg1.PrivateKey
	originalKid := cfg1.PrivateKeyID

	// Rotate.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected success, got error: %v", resp)
	}

	// Verify the key and kid have changed.
	cfg2, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	if cfg2.PrivateKey == originalKey {
		t.Fatal("expected key to change after rotation")
	}
	if cfg2.PrivateKeyID == originalKid {
		t.Fatal("expected kid to change after rotation")
	}
	if cfg2.KeySource != "internal" {
		t.Fatalf("expected key_source=internal, got %q", cfg2.KeySource)
	}
}

func TestRotateRootPrivateKeyJWTEC(t *testing.T) {
	b, storage := newTestBackend(t)

	// Write config with ES256 auto-generated key.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "ec-rotate-client",
			"signing_algorithm": "ES256",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	cfg1, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	originalKey := cfg1.PrivateKey
	originalKid := cfg1.PrivateKeyID

	// Rotate.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected success, got error: %v", resp)
	}
	if resp.Data["signing_algorithm"] != "ES256" {
		t.Fatalf("expected signing_algorithm=ES256, got %v", resp.Data["signing_algorithm"])
	}

	cfg2, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	if cfg2.PrivateKey == originalKey {
		t.Fatal("expected key to change after rotation")
	}
	if cfg2.PrivateKeyID == originalKid {
		t.Fatal("expected kid to change after rotation")
	}

	// Verify the rotated key is EC and matches ES256.
	key, err := parsePrivateKey(cfg2.PrivateKey)
	if err != nil {
		t.Fatalf("rotated key is not valid: %v", err)
	}
	if err := validateKeyAlgorithmMatch(key, "ES256"); err != nil {
		t.Fatalf("rotated key does not match algorithm: %v", err)
	}
}

func TestConfigUpdateRetainsKeySource(t *testing.T) {
	b, storage := newTestBackend(t)

	// Create config with auto-generated key.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "original-client",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify initial state.
	cfg, err := getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	if cfg.KeySource != "internal" {
		t.Fatalf("expected key_source=internal, got %q", cfg.KeySource)
	}
	originalKey := cfg.PrivateKey

	// Update only client_id, without providing private_key.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"client_id":         "updated-client",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify key_source is still internal and key didn't change.
	cfg, err = getConfig(context.Background(), storage, "test")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	if cfg.KeySource != "internal" {
		t.Fatalf("expected key_source to remain internal after update, got %q", cfg.KeySource)
	}
	if cfg.PrivateKey != originalKey {
		t.Fatal("expected private key to remain unchanged after update")
	}
	if cfg.ClientID != "updated-client" {
		t.Fatalf("expected client_id=updated-client, got %q", cfg.ClientID)
	}
}

func TestConfigUpdateRejectsAlgorithmMismatch(t *testing.T) {
	b, storage := newTestBackend(t)

	// Create config with auto-generated RSA key (default RS256).
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "mismatch-client",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
			"verify_connection": false,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Try to change signing_algorithm to ES256 without providing a new EC key.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/test",
		Storage:   storage,
		Data: map[string]any{
			"signing_algorithm": "ES256",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for algorithm mismatch with retained RSA key")
	}
}

func TestCredsReadDefaultScope(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-default-scope", nil)

	server := newMockTokenServer(t, func(r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("scope") != "openid" {
			t.Fatalf("expected scope=openid (from default_scope), got %q", r.FormValue("scope"))
		}
	})
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"client_id":         "admin-client",
		"client_secret":     "admin-secret",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, map[string]any{
		"default_scope": "openid",
	})

	// Request creds without specifying scope — should use default_scope from role.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-default-scope",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
	if resp.Data["access_token"] != "brokered-jwt-token" {
		t.Fatalf("expected access_token=brokered-jwt-token, got %v", resp.Data["access_token"])
	}
}

func TestCredsReadScopeOverridesDefault(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-override-scope", nil)

	server := newMockTokenServer(t, func(r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("scope") != "email" {
			t.Fatalf("expected scope=email (caller override), got %q", r.FormValue("scope"))
		}
	})
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"client_id":         "admin-client",
		"client_secret":     "admin-secret",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, map[string]any{
		"default_scope": "openid",
	})

	// Request creds with explicit scope — should override default_scope.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-override-scope",
		Data: map[string]any{
			"scope": "email",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
}

func TestCredsReadScopeNotInAllowedScopes(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-bad-scope", nil)

	server := newMockTokenServer(t, nil)
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"client_id":         "admin-client",
		"client_secret":     "admin-secret",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, map[string]any{
		"allowed_scopes": "openid,email",
	})

	// Request creds with a scope not in allowed_scopes.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-bad-scope",
		Data: map[string]any{
			"scope": "admin",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for disallowed scope")
	}
	if !strings.Contains(resp.Error().Error(), "admin") {
		t.Fatalf("expected error to mention 'admin', got: %s", resp.Error())
	}
}

func TestCredsReadScopeInAllowedScopes(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-good-scope", nil)

	server := newMockTokenServer(t, func(r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("scope") != "openid email" {
			t.Fatalf("expected scope='openid email', got %q", r.FormValue("scope"))
		}
	})
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"client_id":         "admin-client",
		"client_secret":     "admin-secret",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, map[string]any{
		"allowed_scopes": "openid,email,profile",
	})

	// Request creds with allowed scopes.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-good-scope",
		Data: map[string]any{
			"scope": "openid email",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
}

func TestCredsReadNoScopeNoDefaultNoAllowed(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-no-scope", nil)

	server := newMockTokenServer(t, func(r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("scope") != "" {
			t.Fatalf("expected no scope param, got %q", r.FormValue("scope"))
		}
	})
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"client_id":         "admin-client",
		"client_secret":     "admin-secret",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, nil)

	// No scope, no default — should pass through without scope param.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-no-scope",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
}

// --- Verify Connection Tests ---

func TestVerifyConnection(t *testing.T) {
	tests := []struct {
		name          string
		serverHandler http.HandlerFunc
		configData    map[string]any
		expectError   bool
		expectPersist bool
	}{
		{
			name: "client_secret success",
			serverHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(AccessTokenResponse{
					AccessToken: "verify-token",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				})
			}),
			configData: map[string]any{
				"client_id":     "test-client",
				"client_secret": "test-secret",
				"url":           "https://pingfederate.example.com:9999",
			},
			expectError:   false,
			expectPersist: true,
		},
		{
			name: "client_secret failure",
			serverHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			}),
			configData: map[string]any{
				"client_id":     "bad-client",
				"client_secret": "bad-secret",
				"url":           "https://pingfederate.example.com:9999",
			},
			expectError:   true,
			expectPersist: false,
		},
		{
			name: "verify_connection false skips check",
			serverHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			}),
			configData: map[string]any{
				"client_id":         "bad-client",
				"client_secret":     "bad-secret",
				"url":               "https://pingfederate.example.com:9999",
				"verify_connection": false,
			},
			expectError:   false,
			expectPersist: true,
		},
		{
			name: "private_key_jwt success",
			serverHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(AccessTokenResponse{
					AccessToken: "jwt-verify-token",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				})
			}),
			configData: map[string]any{
				"auth_method":       "private_key_jwt",
				"client_id":         "jwt-client",
				"private_key_id":    "key-1",
				"signing_algorithm": "RS256",
				"url":               "https://pingfederate.example.com:9999",
			},
			expectError:   false,
			expectPersist: true,
		},
		{
			name: "private_key_jwt failure",
			serverHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			}),
			configData: map[string]any{
				"auth_method":       "private_key_jwt",
				"client_id":         "jwt-client",
				"private_key_id":    "key-1",
				"signing_algorithm": "RS256",
				"url":               "https://pingfederate.example.com:9999",
			},
			expectError:   true,
			expectPersist: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage := newTestBackend(t)

			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			data := make(map[string]any)
			for k, v := range tt.configData {
				data[k] = v
			}
			data["token_url"] = server.URL

			// For private_key_jwt tests, generate a key if not provided.
			if data["auth_method"] == "private_key_jwt" {
				if _, ok := data["private_key"]; !ok {
					data["private_key"] = testRSAPrivateKeyPEM(t)
				}
			}

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "config/test",
				Storage:   storage,
				Data:      data,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectError {
				if resp == nil || !resp.IsError() {
					t.Fatal("expected error response for failed verification")
				}
				if !strings.Contains(resp.Error().Error(), "failed to verify connection to PingFederate") {
					t.Fatalf("expected verify connection error, got: %s", resp.Error())
				}
			} else {
				if resp != nil && resp.IsError() {
					t.Fatalf("unexpected error response: %v", resp.Error())
				}
			}

			// Check whether config was persisted.
			cfg, err := getConfig(context.Background(), storage, "test")
			if err != nil {
				t.Fatalf("unexpected error reading config: %v", err)
			}
			if tt.expectPersist && cfg == nil {
				t.Fatal("expected config to be persisted, but it was not")
			}
			if !tt.expectPersist && cfg != nil {
				t.Fatal("expected config NOT to be persisted, but it was")
			}
		})
	}
}

// --- Creds with Allowed Metadata Keys Tests ---

func TestCredsReadWithAllowedMetadataKeys(t *testing.T) {
	metadata := map[string]string{
		"team":     "platform",
		"env":      "prod",
		"internal": "secret-value",
	}
	b, storage := newTestBackendWithEntity(t, "entity-meta-filter", metadata)

	server := newMockTokenServer(t, func(r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("team") != "platform" {
			t.Fatalf("expected team=platform, got %q", r.FormValue("team"))
		}
		if r.FormValue("internal") != "" {
			t.Fatalf("expected internal to be absent, got %q", r.FormValue("internal"))
		}
	})
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"client_id":         "admin-client",
		"client_secret":     "admin-secret",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, map[string]any{
		"allowed_metadata_keys": "team,env",
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-meta-filter",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
}

func TestCredsReadWithoutAllowedMetadataKeysSendsAll(t *testing.T) {
	metadata := map[string]string{
		"team":     "platform",
		"env":      "prod",
		"internal": "secret-value",
	}
	b, storage := newTestBackendWithEntity(t, "entity-meta-all", metadata)

	server := newMockTokenServer(t, func(r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		for _, key := range []string{"team", "env", "internal"} {
			if r.FormValue(key) == "" {
				t.Fatalf("expected form parameter %q to be present", key)
			}
		}
	})
	defer server.Close()

	writeCredsPrereqs(t, b, storage, map[string]any{
		"client_id":         "admin-client",
		"client_secret":     "admin-secret",
		"url":               "https://pingfederate.example.com:9999",
		"token_url":         server.URL,
		"verify_connection": false,
	}, nil)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		EntityID:  "entity-meta-all",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
}

func TestConfigDeleteWarnsAboutDependentRoles(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	// Create a role referencing the connection.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/dep-role",
		Storage:   storage,
		Data: map[string]any{
			"connection_name": "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Delete the connection.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response with warnings, got nil")
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("expected warnings about dependent roles")
	}

	found := false
	for _, w := range resp.Warnings {
		if strings.Contains(w, "dep-role") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected warning mentioning dep-role, got %v", resp.Warnings)
	}
}

func TestConfigDeleteWarnsAboutDependentStaticRoles(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	// Create a static role referencing the connection.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/dep-static",
		Storage:   storage,
		Data: map[string]any{
			"connection_name": "test",
			"client_id":       "some-client",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Delete the connection.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response with warnings, got nil")
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("expected warnings about dependent static roles")
	}

	found := false
	for _, w := range resp.Warnings {
		if strings.Contains(w, "dep-static") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected warning mentioning dep-static, got %v", resp.Warnings)
	}
}

func TestConfigDeleteNoWarningWithoutDependents(t *testing.T) {
	b, storage := newTestBackend(t)

	writeTestConfig(t, b, storage)

	// Delete the connection with no roles referencing it.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response when no dependents, got %v", resp)
	}
}
