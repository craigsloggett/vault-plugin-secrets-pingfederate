package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	serverPrefix       = "servers/"
	serverPathTemplate = "servers/%s"
)

// server represents a PingFederate instance. Each server has its own
// URL and KeyRing for signing JWT client assertions.
type server struct {
	isNewEntry bool

	PingURL string `json:"ping_url"`
}

func getServer(ctx context.Context, s logical.Storage, name string) (*server, error) {
	entry, err := s.Get(ctx, fmt.Sprintf(serverPathTemplate, name))
	if err != nil {
		return nil, fmt.Errorf("failed to get server from storage: %w", err)
	}
	if entry == nil {
		return &server{isNewEntry: true}, nil
	}

	var srv server
	if err := entry.DecodeJSON(&srv); err != nil {
		return nil, fmt.Errorf("failed to decode server from storage: %w", err)
	}
	return &srv, nil
}

func storeServer(ctx context.Context, s logical.Storage, name string, srv *server) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf(serverPathTemplate, name), srv)
	if err != nil {
		return fmt.Errorf("failed to serialize server: %w", err)
	}
	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to store server: %w", err)
	}
	return nil
}

func deleteServer(ctx context.Context, s logical.Storage, name string) error {
	return s.Delete(ctx, fmt.Sprintf(serverPathTemplate, name))
}

func listServers(ctx context.Context, s logical.Storage) ([]string, error) {
	names, err := s.List(ctx, serverPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list servers: %w", err)
	}
	return names, nil
}
