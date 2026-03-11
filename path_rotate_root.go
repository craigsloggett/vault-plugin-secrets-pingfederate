package pingfederate

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const walRotateRootKind = "rotateRootCreds"

type walRotateRootEntry struct {
	ConnectionName string `json:"connection_name"`
	NewSecret      string `json:"new_secret"`
}

func pathRotateRoot(b *pingFederateBackend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "ping-federate",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the connection.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.rotateRootOperation,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
				Summary:                     "Rotate the root credentials for a PingFederate connection.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "rotate",
					OperationSuffix: "root-credentials",
				},
			},
		},
		HelpSynopsis:    "Rotate the root credentials for a PingFederate connection.",
		HelpDescription: "Rotate the foothold client secret used to authenticate with the PingFederate admin API.",
	}
}

func (b *pingFederateBackend) rotateRootOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if !atomic.CompareAndSwapInt32(&b.rotateRootLock, 0, 1) {
		return logical.ErrorResponse("root credential rotation already in progress"), nil
	}
	defer atomic.StoreInt32(&b.rotateRootLock, 0)

	name, ok := d.Get("name").(string)
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	cfg, err := getConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("connection %q not configured", name), nil
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

		entry, err := logical.StorageEntryJSON("config/"+name, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage entry: %w", err)
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to write updated config to storage: %w", err)
		}
		b.resetConnection(name)

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

	client, err := b.getClientForConnection(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	newSecret, err := client.UpdateClientSecret(ctx, cfg.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate root credentials in PingFederate: %w", err)
	}

	walID, err := framework.PutWAL(ctx, req.Storage, walRotateRootKind, &walRotateRootEntry{
		ConnectionName: name,
		NewSecret:      newSecret,
	})
	if err != nil {
		b.logRootRotationFailure(cfg.ClientID)
		return nil, fmt.Errorf("failed to write WAL entry: %w", err)
	}

	cfg.ClientSecret = newSecret

	entry, err := logical.StorageEntryJSON("config/"+name, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write updated config to storage: %w", err)
	}

	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		b.Logger().Warn("failed to delete WAL entry; will be cleaned up on next rollback cycle",
			"wal_id", walID,
			"error", err,
		)
	}

	b.resetConnection(name)

	resp := &logical.Response{}
	resp.AddWarning("Root credentials have been rotated. The previous credentials are no longer valid.")
	return resp, nil
}

func (b *pingFederateBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data any) error {
	switch kind {
	case walRotateRootKind:
		return b.walRollbackRotateRoot(ctx, req, data)
	case walStaticRoleCredsKind:
		return b.walRollbackStaticRoleCreds(ctx, req, data)
	default:
		return fmt.Errorf("unknown WAL kind: %q", kind)
	}
}

func (b *pingFederateBackend) walRollbackRotateRoot(ctx context.Context, req *logical.Request, data any) error {
	raw, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("WAL data is not a map: %T", data)
	}

	connName, _ := raw["connection_name"].(string)
	newSecret, _ := raw["new_secret"].(string)
	if connName == "" || newSecret == "" {
		return fmt.Errorf("WAL entry missing required fields")
	}

	cfg, err := getConfig(ctx, req.Storage, connName)
	if err != nil {
		return err
	}
	if cfg == nil {
		return nil
	}

	if cfg.ClientSecret == newSecret {
		return nil
	}

	cfg.ClientSecret = newSecret

	entry, err := logical.StorageEntryJSON("config/"+connName, cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage entry during WAL rollback: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write config during WAL rollback: %w", err)
	}

	b.resetConnection(connName)
	b.Logger().Info("WAL rollback recovered rotated root credentials", "connection", connName)

	return nil
}

func (b *pingFederateBackend) walRollbackStaticRoleCreds(ctx context.Context, req *logical.Request, data any) error {
	raw, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("WAL data is not a map: %T", data)
	}

	roleName, _ := raw["role_name"].(string)
	newSecret, _ := raw["new_secret"].(string)
	if roleName == "" || newSecret == "" {
		return fmt.Errorf("WAL entry missing required fields")
	}

	stored, err := getStaticRoleSecret(ctx, req.Storage, roleName)
	if err != nil {
		return err
	}

	if stored != nil && stored.ClientSecret == newSecret {
		return nil
	}

	if err := putStaticRoleSecret(ctx, req.Storage, roleName, newSecret); err != nil {
		return fmt.Errorf("failed to write static role secret during WAL rollback: %w", err)
	}

	b.Logger().Info("WAL rollback recovered rotated static role credentials", "role", roleName)

	return nil
}

// logRootRotationFailure logs an error when the rotated secret was accepted by
// PingFederate but the WAL entry could not be written. This is a narrow window
// between PingFederate accepting the secret and the WAL being persisted.
func (b *pingFederateBackend) logRootRotationFailure(clientID string) {
	b.Logger().Error("failed to persist rotated root credentials; PingFederate has the new secret but Vault does not",
		"client_id", clientID,
		"action_required", "manually update the plugin config with the current PingFederate credentials",
	)
}
