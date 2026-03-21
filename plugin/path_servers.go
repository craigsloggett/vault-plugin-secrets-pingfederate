package plugin

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathServer(b *PingFederateBackend) *framework.Path {
	return &framework.Path{
		Pattern: "servers/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPing,
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the PingFederate server configuration.",
			},
			"ping_url": {
				Type:        framework.TypeString,
				Description: "Base URL of the PingFederate instance (e.g. https://pingfed.example.com:9031).",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleServerRead,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
					}},
				},
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleServerWrite,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
					}},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleServerWrite,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
					}},
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.handleServerDelete,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
					}},
				},
			},
		},

		ExistenceCheck: b.handleServerExistenceCheck,

		HelpSynopsis:    "Manage PingFederate server configurations.",
		HelpDescription: "This path allows you to configure PingFederate server instances that the plugin will authenticate against.",
	}
}

func pathListServers(b *PingFederateBackend) *framework.Path {
	return &framework.Path{
		Pattern: "servers/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPing,
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleServerList,
			},
		},

		HelpSynopsis:    "List configured PingFederate servers.",
		HelpDescription: "Returns a list of all configured PingFederate server names.",
	}
}

func getName(d *framework.FieldData) (string, error) {
	raw, ok := d.Get("name").(string)
	if !ok || raw == "" {
		return "", fmt.Errorf("server name is required")
	}
	return raw, nil
}

func (b *PingFederateBackend) handleServerRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, err := getName(d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	srv, err := getServer(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if srv.isNewEntry {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"ping_url": srv.PingURL,
		},
	}, nil
}

func (b *PingFederateBackend) handleServerWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, err := getName(d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	srv, err := getServer(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if raw, ok := d.GetOk("ping_url"); ok {
		pingURL, ok := raw.(string)
		if ok {
			srv.PingURL = pingURL
		}
	}

	if srv.PingURL == "" {
		return logical.ErrorResponse("ping_url is required"), nil
	}

	srv.isNewEntry = false
	if err := storeServer(ctx, req.Storage, name, srv); err != nil {
		return nil, fmt.Errorf("failed to store server %q: %w", name, err)
	}

	return &logical.Response{
		Data: map[string]any{
			"ping_url": srv.PingURL,
		},
	}, nil
}

func (b *PingFederateBackend) handleServerDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, err := getName(d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if err := deleteServer(ctx, req.Storage, name); err != nil {
		return nil, fmt.Errorf("failed to delete server %q: %w", name, err)
	}

	return nil, nil
}

func (b *PingFederateBackend) handleServerList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := listServers(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(names), nil
}

func (b *PingFederateBackend) handleServerExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name, err := getName(d)
	if err != nil {
		return false, err
	}

	srv, err := getServer(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}

	return !srv.isNewEntry, nil
}
