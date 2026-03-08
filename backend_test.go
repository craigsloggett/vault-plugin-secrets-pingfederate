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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "admin-client",
			"client_secret": "admin-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response writing config: %v", resp.Error())
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
		Path:      "config",
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
		Path:      "config",
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
		Path:      "config",
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "my-client-id",
			"client_secret": "my-client-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     "https://pingfederate.example.com:9031/as/token.oauth2",
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
		Path:      "config",
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

func TestConfigWriteWithTTL(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "my-client-id",
			"client_secret": "my-client-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     "https://pingfederate.example.com:9031/as/token.oauth2",
			"default_ttl":   3600,
			"max_ttl":       7200,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Data["default_ttl"] != int64(3600) {
		t.Fatalf("expected default_ttl 3600, got %v", resp.Data["default_ttl"])
	}
	if resp.Data["max_ttl"] != int64(7200) {
		t.Fatalf("expected max_ttl 7200, got %v", resp.Data["max_ttl"])
	}
}

func TestConfigUpdate(t *testing.T) {
	b, storage := newTestBackend(t)

	// Create initial config.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "my-client-id",
			"client_secret": "my-client-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Update only the URL.
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"url": "https://pingfederate-new.example.com:9999",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the update preserved existing fields.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
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
		Path:      "config",
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
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response after delete, got %v", resp)
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

	// Write a role.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":      "terraform",
			"client_id": "terraform-client",
			"ttl":       3600,
			"max_ttl":   7200,
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
	if resp.Data["ttl"] != int64(3600) {
		t.Fatalf("expected ttl 3600, got %v", resp.Data["ttl"])
	}
	if resp.Data["max_ttl"] != int64(7200) {
		t.Fatalf("expected max_ttl 7200, got %v", resp.Data["max_ttl"])
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

	// Write a role.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":      "terraform",
			"client_id": "terraform-client",
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

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/test-role",
		Storage:   storage,
		Data: map[string]any{
			"name": "test-role",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing client_id")
	}
}

func TestStaticRoleDelete(t *testing.T) {
	b, storage := newTestBackend(t)

	// Create a role.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":      "terraform",
			"client_id": "terraform-client",
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
	b.client = &mockPingFederateClient{}

	writeTestConfig(t, b, storage)

	// Create a role.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":      "terraform",
			"client_id": "terraform-client",
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
		Name:     "terraform",
		ClientID: "terraform-client",
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

	b.client = &mockPingFederateClient{
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
			"name":      "terraform",
			"client_id": "terraform-client",
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

	b.client = &mockPingFederateClient{
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
		Path:      "rotate-root",
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
	cfg, err := getConfig(context.Background(), storage)
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
		Path:      "rotate-root",
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

	b.client = &mockPingFederateClient{
		updateClientSecretFunc: func(_ context.Context, _ string) (string, error) {
			return "", fmt.Errorf("PingFederate error")
		},
	}

	writeTestConfig(t, b, storage)

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root",
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwt-admin-client",
			"private_key":       testRSAPrivateKeyPEM(t),
			"private_key_id":    "key-1",
			"signing_algorithm": "RS256",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
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
}

func TestConfigWriteJWTDefaultAlgorithm(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":    "private_key_jwt",
			"client_id":      "jwt-admin-client",
			"private_key":    testRSAPrivateKeyPEM(t),
			"private_key_id": "key-1",
			"url":            "https://pingfederate.example.com:9999",
			"token_url":      "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify default signing algorithm was set.
	cfg, err := getConfig(context.Background(), storage)
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method": "private_key_jwt",
			"client_id":   "jwt-admin-client",
			"url":         "https://pingfederate.example.com:9999",
			"token_url":   "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify the stored config has an internally generated key.
	cfg, err := getConfig(context.Background(), storage)
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method": "private_key_jwt",
			"client_id":   "jwt-admin-client",
			"private_key": testRSAPrivateKeyPEM(t),
			"url":         "https://pingfederate.example.com:9999",
			"token_url":   "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	cfg, err := getConfig(context.Background(), storage)
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
		Path:      "config",
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
		Path:      "config",
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
		Path:      "config",
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
		Path:      "config",
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"private_key":       testRSAPrivateKeyPEM(t),
			"private_key_id":    "key-1",
			"signing_algorithm": "RS256",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify client_secret was cleared from storage.
	cfg, err := getConfig(context.Background(), storage)
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":   "client_secret",
			"client_secret": "new-secret",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify JWT fields were cleared from storage.
	cfg, err = getConfig(context.Background(), storage)
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
		Path:      "config",
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
		Path:      "config",
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
		Path:      "rotate-root",
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
	cfg, err := getConfig(context.Background(), storage)
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
	b.client = &mockPingFederateClient{}

	writeTestJWTConfig(t, b, storage)

	// Create a role.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":      "terraform",
			"client_id": "terraform-client",
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

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
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

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
		Data: map[string]any{
			"name":            "terraform",
			"client_id":       "terraform-client",
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
	b.client = &mockPingFederateClient{
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
	b.client = &mockPingFederateClient{
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
	b.client = &mockPingFederateClient{
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
			"name":      "terraform",
			"client_id": "terraform-client",
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
		Path:      "jwks",
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
		Path:      "jwks",
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
		Path:      "jwks",
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwt-admin-client",
			"private_key":       testECPrivateKeyPEM(t),
			"private_key_id":    "ec-key-1",
			"signing_algorithm": "ES256",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
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
		Path:      "jwks",
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

// --- Token Brokering Tests ---

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

func TestTokenReadWithoutConfig(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-123", nil)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token",
		Storage:   storage,
		EntityID:  "entity-123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for unconfigured backend")
	}
}

func TestTokenReadWithoutEntityID(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-123", nil)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token",
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

func TestTokenReadBasicAuth(t *testing.T) {
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

	// Write config with token_url pointing to mock server.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "admin-client",
			"client_secret": "admin-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     server.URL,
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
		Path:      "token",
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

func TestTokenReadJWTAuth(t *testing.T) {
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

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "jwt-admin-client",
			"private_key":       testRSAPrivateKeyPEM(t),
			"private_key_id":    "key-1",
			"signing_algorithm": "RS256",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         server.URL,
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
		Path:      "token",
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

func TestTokenWriteWithScope(t *testing.T) {
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

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "admin-client",
			"client_secret": "admin-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     server.URL,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token",
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

func TestTokenReadReservedMetadataKeysWarning(t *testing.T) {
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

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "admin-client",
			"client_secret": "admin-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     server.URL,
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
		Path:      "token",
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "ec-client",
			"signing_algorithm": "ES256",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	cfg, err := getConfig(context.Background(), storage)
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method": "private_key_jwt",
			"client_id":   "auto-client",
			"url":         "https://pingfederate.example.com:9999",
			"token_url":   "https://pingfederate.example.com:9031/as/token.oauth2",
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
		Path:      "config",
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method": "private_key_jwt",
			"client_id":   "jwks-client",
			"url":         "https://pingfederate.example.com:9999",
			"token_url":   "https://pingfederate.example.com:9031/as/token.oauth2",
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
		Path:      "jwks",
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method": "private_key_jwt",
			"client_id":   "rotate-client",
			"url":         "https://pingfederate.example.com:9999",
			"token_url":   "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Capture the original key and kid.
	cfg1, err := getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	originalKey := cfg1.PrivateKey
	originalKid := cfg1.PrivateKeyID

	// Rotate.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected success, got error: %v", resp)
	}

	// Verify the key and kid have changed.
	cfg2, err := getConfig(context.Background(), storage)
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":       "private_key_jwt",
			"client_id":         "ec-rotate-client",
			"signing_algorithm": "ES256",
			"url":               "https://pingfederate.example.com:9999",
			"token_url":         "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	cfg1, err := getConfig(context.Background(), storage)
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	originalKey := cfg1.PrivateKey
	originalKid := cfg1.PrivateKeyID

	// Rotate.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root",
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

	cfg2, err := getConfig(context.Background(), storage)
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method": "private_key_jwt",
			"client_id":   "original-client",
			"url":         "https://pingfederate.example.com:9999",
			"token_url":   "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify initial state.
	cfg, err := getConfig(context.Background(), storage)
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id": "updated-client",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify key_source is still internal and key didn't change.
	cfg, err = getConfig(context.Background(), storage)
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
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method": "private_key_jwt",
			"client_id":   "mismatch-client",
			"url":         "https://pingfederate.example.com:9999",
			"token_url":   "https://pingfederate.example.com:9031/as/token.oauth2",
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
		Path:      "config",
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

func TestConfigWriteDefaultScopeNotInAllowedScopes(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":      "scope-client",
			"client_secret":  "scope-secret",
			"url":            "https://pingfederate.example.com:9999",
			"token_url":      "https://pingfederate.example.com:9031/as/token.oauth2",
			"default_scope":  "openid profile",
			"allowed_scopes": "openid,email",
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

func TestConfigWriteDefaultScopeWithinAllowedScopes(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":      "scope-client",
			"client_secret":  "scope-secret",
			"url":            "https://pingfederate.example.com:9999",
			"token_url":      "https://pingfederate.example.com:9031/as/token.oauth2",
			"default_scope":  "openid email",
			"allowed_scopes": "openid,email,profile",
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
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error reading config: %v", err)
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

func TestTokenReadDefaultScope(t *testing.T) {
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

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "admin-client",
			"client_secret": "admin-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     server.URL,
			"default_scope": "openid",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Request token without specifying scope — should use default_scope.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token",
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

func TestTokenReadScopeOverridesDefault(t *testing.T) {
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

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "admin-client",
			"client_secret": "admin-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     server.URL,
			"default_scope": "openid",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Request token with explicit scope — should override default_scope.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token",
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

func TestTokenReadScopeNotInAllowedScopes(t *testing.T) {
	b, storage := newTestBackendWithEntity(t, "entity-bad-scope", nil)

	server := newMockTokenServer(t, nil)
	defer server.Close()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":      "admin-client",
			"client_secret":  "admin-secret",
			"url":            "https://pingfederate.example.com:9999",
			"token_url":      server.URL,
			"allowed_scopes": "openid,email",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Request token with a scope not in allowed_scopes.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token",
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

func TestTokenReadScopeInAllowedScopes(t *testing.T) {
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

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":      "admin-client",
			"client_secret":  "admin-secret",
			"url":            "https://pingfederate.example.com:9999",
			"token_url":      server.URL,
			"allowed_scopes": "openid,email,profile",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Request token with allowed scopes.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "token",
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

func TestTokenReadNoScopeNoDefaultNoAllowed(t *testing.T) {
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

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"client_id":     "admin-client",
			"client_secret": "admin-secret",
			"url":           "https://pingfederate.example.com:9999",
			"token_url":     server.URL,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// No scope, no default — should pass through without scope param.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token",
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
