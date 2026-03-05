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

func TestConfigWrite(t *testing.T) {
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
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
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
