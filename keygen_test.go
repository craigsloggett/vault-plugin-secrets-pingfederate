package pingfederate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"
)

func TestGenerateSigningKeyRSA(t *testing.T) {
	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		t.Run(alg, func(t *testing.T) {
			pemStr, err := generateSigningKey(alg)
			if err != nil {
				t.Fatalf("generateSigningKey(%s) error: %v", alg, err)
			}
			if pemStr == "" {
				t.Fatal("expected non-empty PEM")
			}

			key, err := parsePrivateKey(pemStr)
			if err != nil {
				t.Fatalf("parsePrivateKey round-trip failed: %v", err)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("expected *rsa.PrivateKey, got %T", key)
			}
			if rsaKey.N.BitLen() != 4096 {
				t.Fatalf("expected 4096-bit key, got %d-bit", rsaKey.N.BitLen())
			}
			if err := validateKeyAlgorithmMatch(key, alg); err != nil {
				t.Fatalf("key-algorithm mismatch: %v", err)
			}
		})
	}
}

func TestGenerateSigningKeyEC256(t *testing.T) {
	pemStr, err := generateSigningKey("ES256")
	if err != nil {
		t.Fatalf("generateSigningKey(ES256) error: %v", err)
	}

	key, err := parsePrivateKey(pemStr)
	if err != nil {
		t.Fatalf("parsePrivateKey round-trip failed: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", key)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Fatalf("expected P-256 curve, got %v", ecKey.Curve.Params().Name)
	}
	if err := validateKeyAlgorithmMatch(key, "ES256"); err != nil {
		t.Fatalf("key-algorithm mismatch: %v", err)
	}
}

func TestGenerateSigningKeyEC384(t *testing.T) {
	pemStr, err := generateSigningKey("ES384")
	if err != nil {
		t.Fatalf("generateSigningKey(ES384) error: %v", err)
	}

	key, err := parsePrivateKey(pemStr)
	if err != nil {
		t.Fatalf("parsePrivateKey round-trip failed: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", key)
	}
	if ecKey.Curve != elliptic.P384() {
		t.Fatalf("expected P-384 curve, got %v", ecKey.Curve.Params().Name)
	}
	if err := validateKeyAlgorithmMatch(key, "ES384"); err != nil {
		t.Fatalf("key-algorithm mismatch: %v", err)
	}
}

func TestGenerateSigningKeyEC512(t *testing.T) {
	pemStr, err := generateSigningKey("ES512")
	if err != nil {
		t.Fatalf("generateSigningKey(ES512) error: %v", err)
	}

	key, err := parsePrivateKey(pemStr)
	if err != nil {
		t.Fatalf("parsePrivateKey round-trip failed: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", key)
	}
	if ecKey.Curve != elliptic.P521() {
		t.Fatalf("expected P-521 curve, got %v", ecKey.Curve.Params().Name)
	}
	if err := validateKeyAlgorithmMatch(key, "ES512"); err != nil {
		t.Fatalf("key-algorithm mismatch: %v", err)
	}
}

func TestGenerateSigningKeyInvalidAlg(t *testing.T) {
	_, err := generateSigningKey("HS256")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestGeneratedKeyRoundTrip(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256"} {
		t.Run(alg, func(t *testing.T) {
			pemStr, err := generateSigningKey(alg)
			if err != nil {
				t.Fatalf("generateSigningKey error: %v", err)
			}

			// Verify the generated key can be used to build a JWT assertion.
			token, err := buildJWTAssertion("test-client", "https://example.com/token", "test-kid", alg, pemStr)
			if err != nil {
				t.Fatalf("buildJWTAssertion with generated key failed: %v", err)
			}
			if token == "" {
				t.Fatal("expected non-empty JWT token")
			}
		})
	}
}
