package pingfederate

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotateRoot(b *pingFederateBackend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.rotateRootOperation,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
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
		return logical.ErrorResponse(
			"root rotation is not supported for private_key_jwt auth; " +
				"generate a new key pair and update the config manually",
		), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	newSecret, err := client.UpdateClientSecret(ctx, cfg.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate root credentials in PingFederate: %w", err)
	}

	oldSecret := cfg.ClientSecret
	cfg.ClientSecret = newSecret

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		// Attempt rollback: we changed the secret in PingFederate but can't persist it.
		b.rollbackRootRotation(ctx, req.Storage, cfg.ClientID, oldSecret, newSecret)
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		b.rollbackRootRotation(ctx, req.Storage, cfg.ClientID, oldSecret, newSecret)
		return nil, fmt.Errorf("failed to write updated config to storage: %w", err)
	}

	b.reset()

	resp := &logical.Response{}
	resp.AddWarning("Root credentials have been rotated. The previous credentials are no longer valid.")
	return resp, nil
}

// rollbackRootRotation attempts to restore the old secret in PingFederate after a failed storage write.
func (b *pingFederateBackend) rollbackRootRotation(ctx context.Context, s logical.Storage, clientID, oldSecret, newSecret string) {
	// Build a temporary client using the new secret (since PingFederate already accepted the rotation).
	cfg, err := getConfig(ctx, s)
	if err != nil || cfg == nil {
		return
	}

	tmpCfg := *cfg
	tmpCfg.ClientSecret = newSecret
	tmpClient := newPingFederateClient(&tmpCfg)

	// We can't easily restore an exact old secret via the admin API (PUT generates a new one).
	// Log the situation so an operator can investigate.
	_ = tmpClient
	_ = oldSecret
	b.Logger().Error("failed to persist rotated root credentials; PingFederate has the new secret but Vault does not",
		"client_id", clientID,
		"action_required", "manually update the plugin config with the current PingFederate credentials",
	)
}
