package pingfederate

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type pingFederateBackend struct {
	*framework.Backend

	lock sync.RWMutex
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
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
			},
			pathRoles(b),
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
}

const backendHelp = `
The PingFederate secrets engine manages credentials for PingFederate.
`
