package pingfederate

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotateRoot(b *pingFederateBackend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "ping-federate",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.rotateRootOperation,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
				Summary:                     "Rotate the root credentials for the PingFederate connection.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "rotate",
					OperationSuffix: "root-credentials",
				},
			},
		},
		HelpSynopsis:    "Rotate the root credentials for the PingFederate connection.",
		HelpDescription: "Rotate the foothold client secret used to authenticate with the PingFederate admin API.",
	}
}

func (b *pingFederateBackend) rotateRootOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if !atomic.CompareAndSwapInt32(&b.rotateRootLock, 0, 1) {
		return logical.ErrorResponse("root credential rotation already in progress"), nil
	}
	defer atomic.StoreInt32(&b.rotateRootLock, 0)

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("backend not configured"), nil
	}

	if cfg.AuthMethod == "private_key_jwt" {
		alg := cfg.SigningAlgorithm
		if alg == "" {
			alg = "RS256"
		}
		newPEM, err := generateSigningKey(alg)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new signing key: %w", err)
		}
		kid, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key ID: %w", err)
		}
		cfg.PrivateKey = newPEM
		cfg.PrivateKeyID = kid
		cfg.KeySource = "internal"

		entry, err := logical.StorageEntryJSON("config", cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage entry: %w", err)
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to write updated config to storage: %w", err)
		}
		b.reset()

		resp := &logical.Response{
			Data: map[string]any{
				"private_key_id":    kid,
				"signing_algorithm": alg,
				"key_source":        "internal",
			},
		}
		resp.AddWarning("Signing key has been rotated. PingFederate will pick up the new public key from the JWKS endpoint.")
		resp.AddWarning("This plugin is currently in beta. Interfaces and behavior may change in future releases.")
		return resp, nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	newSecret, err := client.UpdateClientSecret(ctx, cfg.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate root credentials in PingFederate: %w", err)
	}

	cfg.ClientSecret = newSecret

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		b.logRootRotationFailure(cfg.ClientID)
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		b.logRootRotationFailure(cfg.ClientID)
		return nil, fmt.Errorf("failed to write updated config to storage: %w", err)
	}

	b.reset()

	resp := &logical.Response{}
	resp.AddWarning("Root credentials have been rotated. The previous credentials are no longer valid.")
	return resp, nil
}

// logRootRotationFailure logs an error when the rotated secret was accepted by
// PingFederate but could not be persisted to Vault storage. Although the plugin
// sends a specific secret via PUT, automatic rollback is not currently
// implemented — the old secret is discarded before the storage write attempt.
func (b *pingFederateBackend) logRootRotationFailure(clientID string) {
	b.Logger().Error("failed to persist rotated root credentials; PingFederate has the new secret but Vault does not",
		"client_id", clientID,
		"action_required", "manually update the plugin config with the current PingFederate credentials",
	)
}
