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

func TestJWTUpdateClientSecret(t *testing.T) {
	rsaKey, rsaPEM := generateTestRSAKey(t)

	var receivedSecret string
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
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
	if secret != receivedSecret {
		t.Fatalf("returned secret %q does not match sent secret %q", secret, receivedSecret)
	}
}

func TestJWTUpdateClientSecretUnauthorized(t *testing.T) {
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

	_, err := client.UpdateClientSecret(context.Background(), "test-client")
	if err == nil {
		t.Fatal("expected error for unauthorized request")
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

func TestJWTUpdateClientSecretWithECKey(t *testing.T) {
	ecKey, ecPEM := generateTestECKey(t, elliptic.P256())

	var receivedSecret string
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

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		receivedSecret = body["secret"]

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"encryptedSecret":"OBF:encrypted"}`))
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
