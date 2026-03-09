package pingfederate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetBrokeredTokenBasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}

		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Fatal("expected Basic Auth header")
		}
		if user != "foothold-client" || pass != "foothold-secret" {
			t.Fatalf("unexpected Basic Auth: %s:%s", user, pass)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Fatalf("expected grant_type=client_credentials, got %q", r.FormValue("grant_type"))
		}
		if r.FormValue("vault_entity_id") != "entity-123" {
			t.Fatalf("expected vault_entity_id=entity-123, got %q", r.FormValue("vault_entity_id"))
		}
		if r.FormValue("scope") != "openid" {
			t.Fatalf("expected scope=openid, got %q", r.FormValue("scope"))
		}
		if r.FormValue("team") != "platform" {
			t.Fatalf("expected team=platform, got %q", r.FormValue("team"))
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(AccessTokenResponse{
			AccessToken: "brokered-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	cfg := &pingFederateConfig{
		AuthMethod:   "client_secret",
		ClientID:     "foothold-client",
		ClientSecret: "foothold-secret",
		TokenURL:     server.URL,
	}

	resp, skipped, err := getBrokeredToken(context.Background(), server.Client(), cfg, "openid", "entity-123", map[string]string{"team": "platform"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("expected no skipped keys, got %v", skipped)
	}
	if resp.AccessToken != "brokered-token" {
		t.Fatalf("expected access_token=brokered-token, got %q", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %q", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Fatalf("expected expires_in=3600, got %d", resp.ExpiresIn)
	}
}

func TestGetBrokeredTokenJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should NOT have Basic Auth.
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
		if r.FormValue("client_id") != "jwt-client" {
			t.Fatalf("expected client_id=jwt-client, got %q", r.FormValue("client_id"))
		}
		if r.FormValue("vault_entity_id") != "entity-456" {
			t.Fatalf("expected vault_entity_id=entity-456, got %q", r.FormValue("vault_entity_id"))
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(AccessTokenResponse{
			AccessToken: "jwt-brokered-token",
			TokenType:   "Bearer",
			ExpiresIn:   7200,
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	cfg := &pingFederateConfig{
		AuthMethod:       "private_key_jwt",
		ClientID:         "jwt-client",
		PrivateKey:       keyPEM,
		PrivateKeyID:     "key-1",
		SigningAlgorithm: "RS256",
		TokenURL:         server.URL,
	}

	resp, _, err := getBrokeredToken(context.Background(), server.Client(), cfg, "", "entity-456", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "jwt-brokered-token" {
		t.Fatalf("expected access_token=jwt-brokered-token, got %q", resp.AccessToken)
	}
}

func TestGetBrokeredTokenNoScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("scope") != "" {
			t.Fatalf("expected no scope param, got %q", r.FormValue("scope"))
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(AccessTokenResponse{
			AccessToken: "no-scope-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	cfg := &pingFederateConfig{
		ClientID:     "client",
		ClientSecret: "secret",
		TokenURL:     server.URL,
	}

	resp, _, err := getBrokeredToken(context.Background(), server.Client(), cfg, "", "entity-1", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "no-scope-token" {
		t.Fatalf("expected no-scope-token, got %q", resp.AccessToken)
	}
}

func TestGetBrokeredTokenNoMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		// Only grant_type and vault_entity_id should be present.
		for key := range r.PostForm {
			if key != "grant_type" && key != "vault_entity_id" {
				t.Fatalf("unexpected form parameter: %q", key)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(AccessTokenResponse{
			AccessToken: "minimal-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	cfg := &pingFederateConfig{
		ClientID:     "client",
		ClientSecret: "secret",
		TokenURL:     server.URL,
	}

	resp, _, err := getBrokeredToken(context.Background(), server.Client(), cfg, "", "entity-1", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "minimal-token" {
		t.Fatalf("expected minimal-token, got %q", resp.AccessToken)
	}
}

func TestGetBrokeredTokenServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
	}))
	defer server.Close()

	cfg := &pingFederateConfig{
		ClientID:     "client",
		ClientSecret: "secret",
		TokenURL:     server.URL,
	}

	_, _, err := getBrokeredToken(context.Background(), server.Client(), cfg, "", "entity-1", nil, nil)
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestGetBrokeredTokenReservedMetadataKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		// grant_type must not be overwritten.
		if r.FormValue("grant_type") != "client_credentials" {
			t.Fatalf("grant_type was overwritten: got %q", r.FormValue("grant_type"))
		}
		// vault_entity_id must not be overwritten.
		if r.FormValue("vault_entity_id") != "entity-1" {
			t.Fatalf("vault_entity_id was overwritten: got %q", r.FormValue("vault_entity_id"))
		}
		// Safe key should be present.
		if r.FormValue("team") != "platform" {
			t.Fatalf("expected team=platform, got %q", r.FormValue("team"))
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(AccessTokenResponse{
			AccessToken: "reserved-test-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	cfg := &pingFederateConfig{
		ClientID:     "client",
		ClientSecret: "secret",
		TokenURL:     server.URL,
	}

	metadata := map[string]string{
		"grant_type":      "authorization_code",
		"vault_entity_id": "spoofed-entity",
		"client_id":       "evil-client",
		"team":            "platform",
	}

	resp, skipped, err := getBrokeredToken(context.Background(), server.Client(), cfg, "", "entity-1", metadata, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "reserved-test-token" {
		t.Fatalf("expected reserved-test-token, got %q", resp.AccessToken)
	}
	if len(skipped) != 3 {
		t.Fatalf("expected 3 skipped keys, got %d: %v", len(skipped), skipped)
	}

	skippedSet := make(map[string]bool)
	for _, k := range skipped {
		skippedSet[k] = true
	}
	for _, expected := range []string{"grant_type", "vault_entity_id", "client_id"} {
		if !skippedSet[expected] {
			t.Errorf("expected %q to be in skipped keys", expected)
		}
	}
}

func TestGetBrokeredTokenAllowedMetadataKeys(t *testing.T) {
	tests := []struct {
		name                string
		metadata            map[string]string
		allowedMetadataKeys []string
		wantKeys            []string
		wantAbsentKeys      []string
		wantSkipped         int
	}{
		{
			name:                "allowlist filters to allowed keys only",
			metadata:            map[string]string{"team": "platform", "env": "prod", "internal": "secret"},
			allowedMetadataKeys: []string{"team", "env"},
			wantKeys:            []string{"team", "env"},
			wantAbsentKeys:      []string{"internal"},
			wantSkipped:         0,
		},
		{
			name:                "empty allowlist passes all keys",
			metadata:            map[string]string{"team": "platform", "env": "prod"},
			allowedMetadataKeys: nil,
			wantKeys:            []string{"team", "env"},
			wantSkipped:         0,
		},
		{
			name:                "allowed key that is also reserved is still skipped",
			metadata:            map[string]string{"grant_type": "evil", "team": "platform"},
			allowedMetadataKeys: []string{"grant_type", "team"},
			wantKeys:            []string{"team"},
			wantSkipped:         1,
		},
		{
			name:                "allowlist with no matching metadata keys",
			metadata:            map[string]string{"internal": "secret"},
			allowedMetadataKeys: []string{"team"},
			wantAbsentKeys:      []string{"internal"},
			wantSkipped:         0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Fatalf("failed to parse form: %v", err)
				}

				for _, key := range tt.wantKeys {
					if r.FormValue(key) == "" {
						t.Errorf("expected form parameter %q to be present", key)
					}
				}
				for _, key := range tt.wantAbsentKeys {
					if r.FormValue(key) != "" {
						t.Errorf("expected form parameter %q to be absent, got %q", key, r.FormValue(key))
					}
				}

				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(AccessTokenResponse{
					AccessToken: "filtered-token",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}); err != nil {
					t.Fatalf("failed to encode response: %v", err)
				}
			}))
			defer server.Close()

			cfg := &pingFederateConfig{
				ClientID:     "client",
				ClientSecret: "secret",
				TokenURL:     server.URL,
			}

			_, skipped, err := getBrokeredToken(context.Background(), server.Client(), cfg, "", "entity-1", tt.metadata, tt.allowedMetadataKeys)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(skipped) != tt.wantSkipped {
				t.Fatalf("expected %d skipped keys, got %d: %v", tt.wantSkipped, len(skipped), skipped)
			}
		})
	}
}
