package pingfederate

import (
	"context"
	"fmt"
	"strings"
	"sync"

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
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathRotateRoot(b),
			},
			pathStaticRoles(b),
		),
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
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

const backendHelp = `
The PingFederate secrets engine manages credentials for PingFederate.
`
