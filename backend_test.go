package pingfederate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// mockPingFederateClient implements PingFederateClient for testing.
type mockPingFederateClient struct {
	getClientSecretFunc    func(ctx context.Context, clientID string) (string, error)
	updateClientSecretFunc func(ctx context.Context, clientID string) (string, error)
	getAccessTokenFunc     func(ctx context.Context, clientID, clientSecret string) (*AccessTokenResponse, error)
}

func (m *mockPingFederateClient) GetClientSecret(ctx context.Context, clientID string) (string, error) {
	if m.getClientSecretFunc != nil {
		return m.getClientSecretFunc(ctx, clientID)
	}
	return "mock-secret", nil
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

func TestStaticRoleReadEmpty(t *testing.T) {
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

// --- Credential Generation Tests ---

func TestStaticRoleReadGeneratesToken(t *testing.T) {
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

	// Read the role — should return a bearer token.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-roles/terraform",
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

func TestStaticRoleReadWithoutConfig(t *testing.T) {
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

	// Read should fail because backend is not configured.
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-roles/terraform",
		Storage:   storage,
	})
	if err == nil {
		t.Fatal("expected error when reading role without backend config")
	}
}

func TestStaticRoleReadClientError(t *testing.T) {
	b, storage := newTestBackend(t)

	b.client = &mockPingFederateClient{
		getClientSecretFunc: func(_ context.Context, _ string) (string, error) {
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
		Path:      "static-roles/terraform",
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

func TestConfigWriteJWTMissingPrivateKey(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method":    "private_key_jwt",
			"client_id":      "jwt-admin-client",
			"private_key_id": "key-1",
			"url":            "https://pingfederate.example.com:9999",
			"token_url":      "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing private_key")
	}
}

func TestConfigWriteJWTMissingKeyID(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"auth_method": "private_key_jwt",
			"client_id":    "jwt-admin-client",
			"private_key":  testRSAPrivateKeyPEM(t),
			"url":          "https://pingfederate.example.com:9999",
			"token_url":    "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing private_key_id")
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
			"auth_method":    "invalid_method",
			"client_id":      "admin-client",
			"client_secret":  "admin-secret",
			"url":            "https://pingfederate.example.com:9999",
			"token_url":      "https://pingfederate.example.com:9031/as/token.oauth2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for invalid auth_method")
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

func TestRotateRootJWTReturnsError(t *testing.T) {
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
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for rotate-root with private_key_jwt")
	}
}

func TestStaticRoleReadGeneratesTokenJWT(t *testing.T) {
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

	// Read the role — should return a bearer token.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-roles/terraform",
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
