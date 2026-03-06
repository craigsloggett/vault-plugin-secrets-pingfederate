package pingfederate

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type pingFederateBackend struct {
	*framework.Backend

	lock           sync.RWMutex
	client         PingFederateClient
	rotateRootLock int32
}

// Factory returns a configured instance of the backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func backend() *pingFederateBackend {
	b := &pingFederateBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			Root: []string{
				"rotate-root",
			},
			Unauthenticated: []string{
				"jwks",
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathJWKS(b),
				pathRotateRoot(b),
			},
			pathStaticRoles(b),
		),
		BackendType:  logical.TypeLogical,
		Invalidate:   b.invalidate,
		PeriodicFunc: b.periodicFunc,
	}

	return b
}

func (b *pingFederateBackend) invalidate(_ context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *pingFederateBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *pingFederateBackend) getClient(ctx context.Context, s logical.Storage) (PingFederateClient, error) {
	b.lock.RLock()
	if b.client != nil {
		defer b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()

	b.lock.Lock()
	defer b.lock.Unlock()

	if b.client != nil {
		return b.client, nil
	}

	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("backend not configured")
	}

	if cfg.AuthMethod == "private_key_jwt" {
		b.client = newPingFederateJWTClient(cfg)
	} else {
		b.client = newPingFederateClient(cfg)
	}
	return b.client, nil
}

// periodicFunc is called by Vault's rollback manager on a regular interval.
// It checks all static roles for rotation_period and rotates client secrets
// that are due.
func (b *pingFederateBackend) periodicFunc(ctx context.Context, req *logical.Request) error {
	logger := b.Logger()

	roles, err := req.Storage.List(ctx, "static-roles/")
	if err != nil {
		return fmt.Errorf("failed to list static roles: %w", err)
	}

	for _, roleName := range roles {
		if err := b.rotateStaticRoleIfDue(ctx, req.Storage, roleName, logger); err != nil {
			logger.Error("scheduled rotation failed", "role", roleName, "error", err)
		}
	}

	return nil
}

func (b *pingFederateBackend) rotateStaticRoleIfDue(ctx context.Context, s logical.Storage, roleName string, logger hclog.Logger) error {
	role, err := getStaticRole(ctx, s, roleName)
	if err != nil || role == nil {
		return err
	}

	if role.RotationPeriod <= 0 {
		return nil
	}

	if time.Since(role.LastRotated) < role.RotationPeriod {
		return nil
	}

	client, err := b.getClient(ctx, s)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}

	_, err = client.UpdateClientSecret(ctx, role.ClientID)
	if err != nil {
		return fmt.Errorf("failed to rotate secret for client %s: %w", role.ClientID, err)
	}

	role.LastRotated = time.Now()

	entry, err := logical.StorageEntryJSON("static-roles/"+roleName, role)
	if err != nil {
		return fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write role after rotation: %w", err)
	}

	logger.Info("rotated client secret on schedule", "role", roleName, "client_id", role.ClientID)
	return nil
}

const backendHelp = `
The PingFederate secrets engine manages credentials for PingFederate.
`
