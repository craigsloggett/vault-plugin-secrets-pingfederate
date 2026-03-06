package pingfederate

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestJWTGetClientSecret(t *testing.T) {
	rsaKey, rsaPEM := generateTestRSAKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/pf-admin-api/v1/oauth/clients/test-client/clientAuth/clientSecret" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		// Verify JWT Bearer auth.
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			t.Fatalf("expected Bearer auth, got %q", authHeader)
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		parsed, err := jwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatalf("failed to parse JWT: %v", err)
		}

		var claims jwt.Claims
		if err := parsed.Claims(&rsaKey.PublicKey, &claims); err != nil {
			t.Fatalf("failed to verify JWT: %v", err)
		}
		if claims.Issuer != "jwt-admin" {
			t.Fatalf("expected issuer %q, got %q", "jwt-admin", claims.Issuer)
		}

		if r.Header.Get("X-XSRF-Header") != "PingFederate" {
			t.Fatal("missing X-XSRF-Header")
		}

		resp := clientSecretResponse{Secret: "the-secret"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := &pingFederateJWTClient{
		adminURL:         server.URL,
		clientID:         "jwt-admin",
		privateKeyPEM:    rsaPEM,
		privateKeyID:     "key-1",
		signingAlgorithm: "RS256",
		httpClient:       server.Client(),
	}

	secret, err := client.GetClientSecret(context.Background(), "test-client")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "the-secret" {
		t.Fatalf("expected 'the-secret', got %q", secret)
	}
}

func TestJWTGetClientSecretUnauthorized(t *testing.T) {
	_, rsaPEM := generateTestRSAKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
	}))
	defer server.Close()

	client := &pingFederateJWTClient{
		adminURL:         server.URL,
		clientID:         "jwt-admin",
		privateKeyPEM:    rsaPEM,
		privateKeyID:     "key-1",
		signingAlgorithm: "RS256",
		httpClient:       server.Client(),
	}

	_, err := client.GetClientSecret(context.Background(), "test-client")
	if err == nil {
		t.Fatal("expected error for unauthorized request")
	}
}

func TestJWTUpdateClientSecret(t *testing.T) {
	rsaKey, rsaPEM := generateTestRSAKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("expected PUT, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("missing Content-Type header")
		}
		if r.Header.Get("X-XSRF-Header") != "PingFederate" {
			t.Fatal("missing X-XSRF-Header")
		}

		// Verify JWT Bearer auth.
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			t.Fatalf("expected Bearer auth, got %q", authHeader)
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		parsed, err := jwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatalf("failed to parse JWT: %v", err)
		}

		var claims jwt.Claims
		if err := parsed.Claims(&rsaKey.PublicKey, &claims); err != nil {
			t.Fatalf("failed to verify JWT: %v", err)
		}

		resp := clientSecretResponse{Secret: "new-rotated-secret"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := &pingFederateJWTClient{
		adminURL:         server.URL,
		clientID:         "jwt-admin",
		privateKeyPEM:    rsaPEM,
		privateKeyID:     "key-1",
		signingAlgorithm: "RS256",
		httpClient:       server.Client(),
	}

	secret, err := client.UpdateClientSecret(context.Background(), "test-client")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "new-rotated-secret" {
		t.Fatalf("expected 'new-rotated-secret', got %q", secret)
	}
}

func TestJWTGetAccessTokenUsesBasicAuth(t *testing.T) {
	_, rsaPEM := generateTestRSAKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}

		// Verify Basic Auth is used (not JWT) for target client token requests.
		user, pass, ok := r.BasicAuth()
		if !ok || user != "target-client" || pass != "target-secret" {
			t.Fatalf("expected Basic Auth with target-client/target-secret, got user=%q pass=%q ok=%v", user, pass, ok)
		}

		// Verify no Bearer token is present.
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			t.Fatal("expected Basic Auth, not Bearer for GetAccessToken")
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

	client := &pingFederateJWTClient{
		adminURL:         "https://admin.example.com",
		tokenURL:         server.URL,
		clientID:         "jwt-admin",
		privateKeyPEM:    rsaPEM,
		privateKeyID:     "key-1",
		signingAlgorithm: "RS256",
		httpClient:       server.Client(),
	}

	tokenResp, err := client.GetAccessToken(context.Background(), "target-client", "target-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokenResp.AccessToken != "eyJhbGciOiJSUzI1NiJ9.test-token" {
		t.Fatalf("unexpected access_token: %q", tokenResp.AccessToken)
	}
	if tokenResp.TokenType != "Bearer" {
		t.Fatalf("unexpected token_type: %q", tokenResp.TokenType)
	}
}

func TestJWTGetClientSecretWithECKey(t *testing.T) {
	ecKey, ecPEM := generateTestECKey(t, elliptic.P256())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		parsed, err := jwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatalf("failed to parse JWT: %v", err)
		}

		var claims jwt.Claims
		if err := parsed.Claims(&ecKey.PublicKey, &claims); err != nil {
			t.Fatalf("failed to verify JWT: %v", err)
		}

		resp := clientSecretResponse{Secret: "ec-secret"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := &pingFederateJWTClient{
		adminURL:         server.URL,
		clientID:         "ec-admin",
		privateKeyPEM:    ecPEM,
		privateKeyID:     "ec-key-1",
		signingAlgorithm: "ES256",
		httpClient:       server.Client(),
	}

	secret, err := client.GetClientSecret(context.Background(), "test-client")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "ec-secret" {
		t.Fatalf("expected 'ec-secret', got %q", secret)
	}
}
