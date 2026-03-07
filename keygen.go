package pingfederate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// generateSigningKey creates a new private key appropriate for the given
// signing algorithm. RSA and PSS algorithms produce a 4096-bit RSA key;
// EC algorithms produce a key on the matching curve. The key is returned
// as a PEM-encoded PKCS#8 string.
func generateSigningKey(algorithm string) (string, error) {
	upper := strings.ToUpper(algorithm)

	var key any
	var err error

	switch {
	case strings.HasPrefix(upper, "RS") || strings.HasPrefix(upper, "PS"):
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	case upper == "ES256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case upper == "ES384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case upper == "ES512":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return "", fmt.Errorf("unsupported algorithm for key generation: %q", algorithm)
	}

	if err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal key to PKCS#8: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}
