package pingfederate

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// newTestBackend creates a configured backend for testing.
func newTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestBackendFactory(t *testing.T) {
	b, _ := newTestBackend(t)
	if b == nil {
		t.Fatal("expected backend, got nil")
	}
	if b.Type() != logical.TypeLogical {
		t.Fatalf("expected TypeLogical, got %v", b.Type())
	}
}

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
		Data:      map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing required fields")
	}
}

func TestConfigWriteAndRead(t *testing.T) {
	b, storage := newTestBackend(t)

	// Write config.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "my-client-id",
			"client_secret": "my-client-secret",
			"url":           "https://pingfederate.example.com:9999",
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
	if _, exists := resp.Data["client_secret"]; exists {
		t.Fatal("client_secret should not be returned in read response")
	}
}

func TestConfigUpdate(t *testing.T) {
	b, storage := newTestBackend(t)

	// Create initial config.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "my-client-id",
			"client_secret": "my-client-secret",
			"url":           "https://pingfederate.example.com:9999",
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
		Data: map[string]interface{}{
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

	// Create config.
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "my-client-id",
			"client_secret": "my-client-secret",
			"url":           "https://pingfederate.example.com:9999",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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

func TestRoleReadEmpty(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/test-role",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response for nonexistent role, got %v", resp)
	}
}

func TestRoleWrite(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"name": "test-role",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}
}

func TestRoleDelete(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/test-role",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}
}

func TestRoleList(t *testing.T) {
	b, storage := newTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}
}
