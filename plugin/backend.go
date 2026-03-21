package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// operationPrefixPing is used by the framework to generate API
	// documentation. Every path operation is prefixed with this value.
	operationPrefixPing = "ping"

	// backendHelp is displayed when a user runs `vault path-help <mount>/`.
	backendHelp = `
EXPERIMENTAL: This plugin is under active development and is not
intended for production use.

The PingFederate secrets plugin brokers OAuth 2.0 access tokens from
PingFederate using the client_credentials grant with private_key_jwt
client authentication. Vault manages the signing keys and exposes a
JWKS endpoint that PingFederate uses to validate client assertions.
`
)

// Factory is the entry point for the Vault plugin framework. It is called
// once per mount when the secrets engine is enabled.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, fmt.Errorf("failed to setup backend: %w", err)
	}
	return b, nil
}

// PingFederateBackend is the backend that implements the plugin. All state
// hangs off this struct and all path handlers are methods on it.
type PingFederateBackend struct {
	*framework.Backend
}

func newBackend() *PingFederateBackend {
	b := &PingFederateBackend{}

	b.Backend = &framework.Backend{
		BackendType:    logical.TypeLogical,
		Help:           backendHelp,
		InitializeFunc: b.initialize,
		Paths: []*framework.Path{
			pathServer(b),
			pathListServers(b),
		},
		PathsSpecial: &logical.Paths{},
	}

	return b
}

// initialize is called after the mount's storage is writable. This is where
// we confirm the plugin lifecycle completed and log accordingly.
func (b *PingFederateBackend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	b.Logger().Warn("PingFederate secrets engine is EXPERIMENTAL and not intended for production use")
	b.Logger().Info("PingFederate secrets engine initialized")
	return nil
}
