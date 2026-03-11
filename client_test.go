package pingfederate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUpdateClientSecret(t *testing.T) {
	var receivedSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/pf-admin-api/v1/oauth/clients/test-client/clientAuth/clientSecret" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("missing Content-Type header")
		}
		if r.Header.Get("X-XSRF-Header") != "PingFederate" {
			t.Fatal("missing X-XSRF-Header")
		}

		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "admin-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		receivedSecret = body["secret"]
		if receivedSecret == "" {
			t.Fatal("expected secret in request body")
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"encryptedSecret":"OBF:encrypted"}`))
	}))
	defer server.Close()

	client := &pingFederateClient{
		adminURL:             server.URL,
		footholdClientID:     "admin",
		footholdClientSecret: "admin-secret",
		httpClient:           server.Client(),
	}

	secret, err := client.UpdateClientSecret(context.Background(), "test-client")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
	if secret != receivedSecret {
		t.Fatalf("returned secret %q does not match sent secret %q", secret, receivedSecret)
	}
}

func TestUpdateClientSecretError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"internal error"}`))
	}))
	defer server.Close()

	client := &pingFederateClient{
		adminURL:             server.URL,
		footholdClientID:     "admin",
		footholdClientSecret: "admin-secret",
		httpClient:           server.Client(),
	}

	_, err := client.UpdateClientSecret(context.Background(), "test-client")
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestGetAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatal("missing Content-Type header")
		}

		user, pass, ok := r.BasicAuth()
		if !ok || user != "my-client" || pass != "my-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Fatalf("expected grant_type=client_credentials, got %q", r.FormValue("grant_type"))
		}

		resp := AccessTokenResponse{
			AccessToken: "eyJhbGciOiJSUzI1NiJ9.test-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := &pingFederateClient{
		tokenURL:   server.URL,
		httpClient: server.Client(),
	}

	tokenResp, err := client.GetAccessToken(context.Background(), "my-client", "my-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokenResp.AccessToken != "eyJhbGciOiJSUzI1NiJ9.test-token" {
		t.Fatalf("unexpected access_token: %q", tokenResp.AccessToken)
	}
	if tokenResp.TokenType != "Bearer" {
		t.Fatalf("unexpected token_type: %q", tokenResp.TokenType)
	}
	if tokenResp.ExpiresIn != 3600 {
		t.Fatalf("unexpected expires_in: %d", tokenResp.ExpiresIn)
	}
}

func TestNewHTTPClientTimeout(t *testing.T) {
	tests := []struct {
		name        string
		insecureTLS bool
	}{
		{
			name:        "insecure TLS enabled",
			insecureTLS: true,
		},
		{
			name:        "insecure TLS disabled",
			insecureTLS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newHTTPClient(tt.insecureTLS)
			if client.Timeout != 30*time.Second {
				t.Fatalf("expected timeout 30s, got %v", client.Timeout)
			}
		})
	}
}

func TestGetAccessTokenUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer server.Close()

	client := &pingFederateClient{
		tokenURL:   server.URL,
		httpClient: server.Client(),
	}

	_, err := client.GetAccessToken(context.Background(), "bad-client", "bad-secret")
	if err == nil {
		t.Fatal("expected error for unauthorized request")
	}
}
