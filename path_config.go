package pingfederate

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type pingFederateConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	URL          string `json:"url"`
}

func pathConfig(_ *pingFederateBackend) *framework.Path {
	return &framework.Path{
		Pattern:        "config",
		ExistenceCheck: configExistenceCheck,
		Fields: map[string]*framework.FieldSchema{
			"client_id": {
				Type:        framework.TypeString,
				Description: "The OAuth 2.0 client ID for authenticating with PingFederate.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: false,
				},
			},
			"client_secret": {
				Type:        framework.TypeString,
				Description: "The OAuth 2.0 client secret for authenticating with PingFederate.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"url": {
				Type:        framework.TypeString,
				Description: "The base URL of the PingFederate admin API (e.g. https://pingfederate.example.com:9999).",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: configReadOperation,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: configWriteOperation,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: configWriteOperation,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: configDeleteOperation,
			},
		},
		HelpSynopsis:    "Configure the PingFederate connection.",
		HelpDescription: "Configure the connection credentials and URL for the PingFederate admin API.",
	}
}

func configExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func configReadOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"client_id": cfg.ClientID,
			"url":       cfg.URL,
		},
	}, nil
}

func configWriteOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &pingFederateConfig{}
	}

	if clientID, ok := d.GetOk("client_id"); ok {
		cfg.ClientID, _ = clientID.(string)
	}
	if clientSecret, ok := d.GetOk("client_secret"); ok {
		cfg.ClientSecret, _ = clientSecret.(string)
	}
	if rawURL, ok := d.GetOk("url"); ok {
		cfg.URL, _ = rawURL.(string)
	}

	if cfg.ClientID == "" {
		return logical.ErrorResponse("client_id is required"), nil
	}
	if cfg.ClientSecret == "" {
		return logical.ErrorResponse("client_secret is required"), nil
	}
	if cfg.URL == "" {
		return logical.ErrorResponse("url is required"), nil
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write config to storage: %w", err)
	}

	return nil, nil
}

func configDeleteOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "config"); err != nil {
		return nil, fmt.Errorf("failed to delete config from storage: %w", err)
	}

	return nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*pingFederateConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var cfg pingFederateConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return nil, fmt.Errorf("failed to deserialize config: %w", err)
	}

	return &cfg, nil
}
