package pingfederate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type pingFederateConfig struct {
	ClientID     string        `json:"client_id"`
	ClientSecret string        `json:"client_secret"`
	URL          string        `json:"url"`
	TokenURL     string        `json:"token_url"`
	DefaultTTL   time.Duration `json:"default_ttl,omitempty"`
	MaxTTL       time.Duration `json:"max_ttl,omitempty"`
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
			"token_url": {
				Type:        framework.TypeString,
				Description: "The PingFederate OAuth 2.0 token endpoint URL (e.g. https://pingfederate.example.com:9031/as/token.oauth2).",
				Required:    true,
			},
			"default_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default TTL for generated credentials. If not set, uses Vault's system default.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum TTL for generated credentials. If not set, uses Vault's system max.",
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

	data := map[string]any{
		"client_id": cfg.ClientID,
		"url":       cfg.URL,
		"token_url": cfg.TokenURL,
	}
	if cfg.DefaultTTL > 0 {
		data["default_ttl"] = int64(cfg.DefaultTTL.Seconds())
	}
	if cfg.MaxTTL > 0 {
		data["max_ttl"] = int64(cfg.MaxTTL.Seconds())
	}

	return &logical.Response{
		Data: data,
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
	if tokenURL, ok := d.GetOk("token_url"); ok {
		cfg.TokenURL, _ = tokenURL.(string)
	}
	if v, ok := d.GetOk("default_ttl"); ok {
		if seconds, ok := v.(int); ok {
			cfg.DefaultTTL = time.Duration(int64(seconds) * int64(time.Second))
		}
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		if seconds, ok := v.(int); ok {
			cfg.MaxTTL = time.Duration(int64(seconds) * int64(time.Second))
		}
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
	if cfg.TokenURL == "" {
		return logical.ErrorResponse("token_url is required"), nil
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
