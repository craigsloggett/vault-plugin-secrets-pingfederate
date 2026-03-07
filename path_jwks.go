package pingfederate

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathJWKS(_ *pingFederateBackend) *framework.Path {
	return &framework.Path{
		Pattern: "jwks",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "ping-federate",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: jwksReadOperation,
				Summary:  "Retrieve the JSON Web Key Set (JWKS) for private_key_jwt authentication.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "jwks",
				},
			},
		},
		HelpSynopsis:    "Retrieve the JSON Web Key Set (JWKS).",
		HelpDescription: "Returns the public key(s) in JWKS format for PingFederate to validate JWT client assertions. Only populated when auth_method is private_key_jwt.",
	}
}

func jwksReadOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	emptyJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}

	if cfg == nil || cfg.AuthMethod != "private_key_jwt" || cfg.PrivateKey == "" {
		return jwksResponse(emptyJWKS)
	}

	key, err := parsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configured private key: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key type %T does not implement crypto.Signer", key)
	}

	jwk := jose.JSONWebKey{
		Key:       signer.Public(),
		KeyID:     cfg.PrivateKeyID,
		Algorithm: cfg.SigningAlgorithm,
		Use:       "sig",
	}

	return jwksResponse(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

func jwksResponse(jwks jose.JSONWebKeySet) (*logical.Response, error) {
	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWKS: %w", err)
	}

	var respData map[string]any
	if err := json.Unmarshal(jwksJSON, &respData); err != nil {
		return nil, fmt.Errorf("failed to prepare JWKS response: %w", err)
	}

	respData[logical.HTTPContentType] = "application/json"
	respData[logical.HTTPRawBody] = string(jwksJSON)
	respData[logical.HTTPStatusCode] = 200

	return &logical.Response{Data: respData}, nil
}
