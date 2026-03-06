package pingfederate

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/go-uuid"
)

// supportedAlgorithms lists all JWT signing algorithms accepted by PingFederate.
var supportedAlgorithms = map[string]jose.SignatureAlgorithm{
	"RS256": jose.RS256,
	"RS384": jose.RS384,
	"RS512": jose.RS512,
	"ES256": jose.ES256,
	"ES384": jose.ES384,
	"ES512": jose.ES512,
	"PS256": jose.PS256,
	"PS384": jose.PS384,
	"PS512": jose.PS512,
}

// buildJWTAssertion creates a signed JWT assertion per RFC 7523 for PingFederate authentication.
func buildJWTAssertion(clientID, audience, keyID, signingAlgorithm, privateKeyPEM string) (string, error) {
	key, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	alg, err := algorithmToJose(signingAlgorithm)
	if err != nil {
		return "", err
	}

	if err := validateKeyAlgorithmMatch(key, signingAlgorithm); err != nil {
		return "", err
	}

	signingKey := jose.SigningKey{Algorithm: alg, Key: key}
	opts := &jose.SignerOptions{}
	opts.WithHeader(jose.HeaderKey("kid"), keyID)
	opts.WithType("JWT")

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT signer: %w", err)
	}

	jti, err := uuid.GenerateUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT ID: %w", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:   clientID,
		Subject:  clientID,
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(now),
		ID:       jti,
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return token, nil
}

// parsePrivateKey decodes a PEM-encoded private key. Supports PKCS8, PKCS1 (RSA), and EC formats.
func parsePrivateKey(pemData string) (any, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key data")
	}

	// Try PKCS8 first (most common modern format).
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS1 RSA.
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try EC.
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key: unsupported key format (tried PKCS8, PKCS1, EC)")
}

// algorithmToJose maps a signing algorithm string to a go-jose SignatureAlgorithm.
func algorithmToJose(alg string) (jose.SignatureAlgorithm, error) {
	joseAlg, ok := supportedAlgorithms[strings.ToUpper(alg)]
	if !ok {
		return "", fmt.Errorf("unsupported signing algorithm %q; supported: RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512", alg)
	}
	return joseAlg, nil
}

// validateKeyAlgorithmMatch ensures the private key type is compatible with the signing algorithm.
func validateKeyAlgorithmMatch(key any, alg string) error {
	upper := strings.ToUpper(alg)

	switch key.(type) {
	case *rsa.PrivateKey:
		if strings.HasPrefix(upper, "RS") || strings.HasPrefix(upper, "PS") {
			return nil
		}
		return fmt.Errorf("RSA private key is not compatible with algorithm %q; use RS* or PS* algorithms", alg)
	case *ecdsa.PrivateKey:
		if strings.HasPrefix(upper, "ES") {
			return nil
		}
		return fmt.Errorf("EC private key is not compatible with algorithm %q; use ES* algorithms", alg)
	default:
		return fmt.Errorf("unsupported private key type %T", key)
	}
}
