package pingfederate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal RSA key: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return key, string(pemBlock)
}

func generateTestECKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return key, string(pemBlock)
}

func TestBuildJWTAssertionRSA(t *testing.T) {
	rsaKey, rsaPEM := generateTestRSAKey(t)

	token, err := buildJWTAssertion("test-client", "https://pf.example.com", "key-1", "RS256", rsaPEM)
	if err != nil {
		t.Fatalf("buildJWTAssertion failed: %v", err)
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	var claims jwt.Claims
	if err := parsed.Claims(&rsaKey.PublicKey, &claims); err != nil {
		t.Fatalf("failed to verify JWT claims: %v", err)
	}

	if claims.Issuer != "test-client" {
		t.Errorf("expected issuer %q, got %q", "test-client", claims.Issuer)
	}
	if claims.Subject != "test-client" {
		t.Errorf("expected subject %q, got %q", "test-client", claims.Subject)
	}
	if !claims.Audience.Contains("https://pf.example.com") {
		t.Errorf("expected audience to contain %q, got %v", "https://pf.example.com", claims.Audience)
	}
	if claims.ID == "" {
		t.Error("expected non-empty JWT ID (jti)")
	}
	if claims.IssuedAt == nil {
		t.Error("expected non-nil issued at (iat)")
	}
	if claims.Expiry == nil {
		t.Error("expected non-nil expiry (exp)")
	} else {
		expectedExpiry := time.Now().Add(5 * time.Minute)
		if claims.Expiry.Time().Before(time.Now()) || claims.Expiry.Time().After(expectedExpiry.Add(time.Second)) {
			t.Errorf("expiry %v is not within expected range", claims.Expiry.Time())
		}
	}
}

func TestBuildJWTAssertionEC(t *testing.T) {
	ecKey, ecPEM := generateTestECKey(t, elliptic.P256())

	token, err := buildJWTAssertion("ec-client", "https://pf.example.com", "ec-key-1", "ES256", ecPEM)
	if err != nil {
		t.Fatalf("buildJWTAssertion failed: %v", err)
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	var claims jwt.Claims
	if err := parsed.Claims(&ecKey.PublicKey, &claims); err != nil {
		t.Fatalf("failed to verify JWT claims: %v", err)
	}

	if claims.Issuer != "ec-client" {
		t.Errorf("expected issuer %q, got %q", "ec-client", claims.Issuer)
	}
}

func TestBuildJWTAssertionPS256(t *testing.T) {
	rsaKey, rsaPEM := generateTestRSAKey(t)

	token, err := buildJWTAssertion("ps-client", "https://pf.example.com", "ps-key", "PS256", rsaPEM)
	if err != nil {
		t.Fatalf("buildJWTAssertion failed: %v", err)
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	var claims jwt.Claims
	if err := parsed.Claims(&rsaKey.PublicKey, &claims); err != nil {
		t.Fatalf("failed to verify JWT claims: %v", err)
	}

	if claims.Issuer != "ps-client" {
		t.Errorf("expected issuer %q, got %q", "ps-client", claims.Issuer)
	}
}

func TestBuildJWTAssertionUniqueJTI(t *testing.T) {
	_, rsaPEM := generateTestRSAKey(t)

	token1, err := buildJWTAssertion("client", "https://pf.example.com", "key", "RS256", rsaPEM)
	if err != nil {
		t.Fatalf("first buildJWTAssertion failed: %v", err)
	}

	token2, err := buildJWTAssertion("client", "https://pf.example.com", "key", "RS256", rsaPEM)
	if err != nil {
		t.Fatalf("second buildJWTAssertion failed: %v", err)
	}

	if token1 == token2 {
		t.Error("expected unique JWTs (different jti), got identical tokens")
	}
}

func TestBuildJWTAssertionInvalidKey(t *testing.T) {
	_, err := buildJWTAssertion("client", "https://pf.example.com", "key", "RS256", "not-a-pem")
	if err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
}

func TestBuildJWTAssertionInvalidAlgorithm(t *testing.T) {
	_, rsaPEM := generateTestRSAKey(t)

	_, err := buildJWTAssertion("client", "https://pf.example.com", "key", "INVALID", rsaPEM)
	if err == nil {
		t.Error("expected error for invalid algorithm, got nil")
	}
}

func TestBuildJWTAssertionKeyAlgorithmMismatch(t *testing.T) {
	_, rsaPEM := generateTestRSAKey(t)

	_, err := buildJWTAssertion("client", "https://pf.example.com", "key", "ES256", rsaPEM)
	if err == nil {
		t.Error("expected error for RSA key with ES256, got nil")
	}
}

func TestParsePrivateKeyPKCS1(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	der := x509.MarshalPKCS1PrivateKey(rsaKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	key, err := parsePrivateKey(string(pemBlock))
	if err != nil {
		t.Fatalf("parsePrivateKey failed: %v", err)
	}

	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", key)
	}
}

func TestParsePrivateKeyEC(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	key, err := parsePrivateKey(string(pemBlock))
	if err != nil {
		t.Fatalf("parsePrivateKey failed: %v", err)
	}

	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
	}
}

func TestParsePrivateKeyInvalid(t *testing.T) {
	_, err := parsePrivateKey("not-a-pem")
	if err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
}

func TestAlgorithmToJose(t *testing.T) {
	tests := []struct {
		input    string
		expected jose.SignatureAlgorithm
	}{
		{"RS256", jose.RS256},
		{"RS384", jose.RS384},
		{"RS512", jose.RS512},
		{"ES256", jose.ES256},
		{"ES384", jose.ES384},
		{"ES512", jose.ES512},
		{"PS256", jose.PS256},
		{"PS384", jose.PS384},
		{"PS512", jose.PS512},
	}

	for _, tt := range tests {
		alg, err := algorithmToJose(tt.input)
		if err != nil {
			t.Errorf("algorithmToJose(%q) returned error: %v", tt.input, err)
		}
		if alg != tt.expected {
			t.Errorf("algorithmToJose(%q) = %v, want %v", tt.input, alg, tt.expected)
		}
	}
}

func TestAlgorithmToJoseInvalid(t *testing.T) {
	_, err := algorithmToJose("INVALID")
	if err == nil {
		t.Error("expected error for invalid algorithm, got nil")
	}
}

func TestValidateKeyAlgorithmMatch(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	// Valid combinations.
	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		if err := validateKeyAlgorithmMatch(rsaKey, alg); err != nil {
			t.Errorf("expected RSA key to be valid with %s, got error: %v", alg, err)
		}
	}
	for _, alg := range []string{"ES256", "ES384", "ES512"} {
		if err := validateKeyAlgorithmMatch(ecKey, alg); err != nil {
			t.Errorf("expected EC key to be valid with %s, got error: %v", alg, err)
		}
	}

	// Invalid combinations.
	if err := validateKeyAlgorithmMatch(rsaKey, "ES256"); err == nil {
		t.Error("expected error for RSA key with ES256")
	}
	if err := validateKeyAlgorithmMatch(ecKey, "RS256"); err == nil {
		t.Error("expected error for EC key with RS256")
	}
}
