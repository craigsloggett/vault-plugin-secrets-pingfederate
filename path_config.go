package pingfederate

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type pingFederateConfig struct {
	AuthMethod       string `json:"auth_method,omitempty"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret,omitempty"`
	AdminUsername    string `json:"admin_username,omitempty"`
	AdminPassword    string `json:"admin_password,omitempty"`
	PrivateKey       string `json:"private_key,omitempty"`
	PrivateKeyID     string `json:"private_key_id,omitempty"`
	SigningAlgorithm string `json:"signing_algorithm,omitempty"`
	URL              string `json:"url"`
	TokenURL         string `json:"token_url"`
	InsecureTLS      bool   `json:"insecure_tls,omitempty"`
	KeySource        string `json:"key_source,omitempty"`
}

func pathConfig(b *pingFederateBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern:        "config/" + framework.GenericNameRegex("name"),
			ExistenceCheck: b.configExistenceCheck,
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "ping-federate",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the connection.",
					Required:    true,
				},
				"auth_method": {
					Type:        framework.TypeString,
					Description: `Authentication method for PingFederate: "client_secret" or "private_key_jwt". Defaults to "client_secret".`,
				},
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
					Description: "The OAuth 2.0 client secret for authenticating with PingFederate. Required when auth_method is client_secret.",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"admin_username": {
					Type:        framework.TypeString,
					Description: "Username for PingFederate admin API authentication. If set, admin API operations use these credentials instead of the foothold client credentials.",
				},
				"admin_password": {
					Type:        framework.TypeString,
					Description: "Password for PingFederate admin API authentication.",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"private_key": {
					Type:        framework.TypeString,
					Description: "PEM-encoded private key for private_key_jwt authentication. If omitted, a key is generated internally.",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"private_key_id": {
					Type:        framework.TypeString,
					Description: "Key ID (kid) to include in JWT headers. If omitted, a UUID is generated automatically.",
				},
				"signing_algorithm": {
					Type:        framework.TypeString,
					Description: "JWT signing algorithm. One of: RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512. Defaults to RS256.",
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
				"insecure_tls": {
					Type:        framework.TypeBool,
					Description: "If true, skip TLS certificate verification when connecting to PingFederate. Not recommended for production.",
				},
				"verify_connection": {
					Type:        framework.TypeBool,
					Default:     true,
					Description: "If true, verify connectivity to PingFederate before accepting the configuration.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.configReadOperation,
					Summary:  "Read a PingFederate connection configuration.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "configuration",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback:                    b.configWriteOperation,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
					Summary:                     "Configure a PingFederate connection.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "configure",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.configWriteOperation,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
					Summary:                     "Configure a PingFederate connection.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "configure",
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback:                    b.configDeleteOperation,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
					Summary:                     "Delete a PingFederate connection configuration.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "configuration",
					},
				},
			},
			HelpSynopsis:    "Configure a PingFederate connection.",
			HelpDescription: "Configure the connection credentials and URLs for a PingFederate instance.",
		},
		{
			Pattern: "config/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "ping-federate",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.configListOperation,
					Summary:  "List configured PingFederate connections.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "connections",
					},
				},
			},
			HelpSynopsis:    "List configured connections.",
			HelpDescription: "List configured PingFederate connections by name.",
		},
	}
}

func (b *pingFederateBackend) configExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name, ok := d.Get("name").(string)
	if !ok {
		return false, nil
	}
	entry, err := req.Storage.Get(ctx, "config/"+name)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *pingFederateBackend) configReadOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.Get("name").(string)
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	cfg, err := getConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	authMethod := cfg.AuthMethod
	if authMethod == "" {
		authMethod = "client_secret"
	}

	data := map[string]any{
		"auth_method":  authMethod,
		"client_id":    cfg.ClientID,
		"url":          cfg.URL,
		"token_url":    cfg.TokenURL,
		"insecure_tls": cfg.InsecureTLS,
	}
	if cfg.SigningAlgorithm != "" {
		data["signing_algorithm"] = cfg.SigningAlgorithm
	}
	if cfg.PrivateKeyID != "" {
		data["private_key_id"] = cfg.PrivateKeyID
	}
	if cfg.KeySource != "" {
		data["key_source"] = cfg.KeySource
	}
	if cfg.AdminUsername != "" {
		data["admin_username"] = cfg.AdminUsername
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *pingFederateBackend) configWriteOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.Get("name").(string)
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	cfg, err := getConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &pingFederateConfig{}
	}

	if v, ok := d.GetOk("auth_method"); ok {
		cfg.AuthMethod, _ = v.(string)
	}
	if clientID, ok := d.GetOk("client_id"); ok {
		cfg.ClientID, _ = clientID.(string)
	}
	if clientSecret, ok := d.GetOk("client_secret"); ok {
		cfg.ClientSecret, _ = clientSecret.(string)
	}
	if v, ok := d.GetOk("admin_username"); ok {
		cfg.AdminUsername, _ = v.(string)
	}
	if v, ok := d.GetOk("admin_password"); ok {
		cfg.AdminPassword, _ = v.(string)
	}
	if v, ok := d.GetOk("private_key"); ok {
		cfg.PrivateKey, _ = v.(string)
	}
	if v, ok := d.GetOk("private_key_id"); ok {
		cfg.PrivateKeyID, _ = v.(string)
	}
	if v, ok := d.GetOk("signing_algorithm"); ok {
		cfg.SigningAlgorithm, _ = v.(string)
	}
	if rawURL, ok := d.GetOk("url"); ok {
		cfg.URL, _ = rawURL.(string)
	}
	if tokenURL, ok := d.GetOk("token_url"); ok {
		cfg.TokenURL, _ = tokenURL.(string)
	}
	if v, ok := d.GetOk("insecure_tls"); ok {
		cfg.InsecureTLS, _ = v.(bool)
	}

	if cfg.ClientID == "" {
		return logical.ErrorResponse("client_id is required"), nil
	}
	if cfg.URL == "" {
		return logical.ErrorResponse("url is required"), nil
	}
	if cfg.TokenURL == "" {
		return logical.ErrorResponse("token_url is required"), nil
	}

	switch cfg.AuthMethod {
	case "", "client_secret":
		if cfg.ClientSecret == "" {
			return logical.ErrorResponse("client_secret is required when auth_method is client_secret"), nil
		}
		// Clear JWT fields so stale sensitive material doesn't persist.
		cfg.PrivateKey = ""
		cfg.PrivateKeyID = ""
		cfg.SigningAlgorithm = ""
		cfg.KeySource = ""
	case "private_key_jwt":
		if cfg.SigningAlgorithm == "" {
			cfg.SigningAlgorithm = "RS256"
		}
		if _, err := algorithmToJose(cfg.SigningAlgorithm); err != nil {
			return logical.ErrorResponse("invalid signing_algorithm: %s", err), nil
		}
		_, keyProvidedInRequest := d.GetOk("private_key")
		if cfg.PrivateKey == "" {
			generatedPEM, err := generateSigningKey(cfg.SigningAlgorithm)
			if err != nil {
				return nil, fmt.Errorf("failed to generate signing key: %w", err)
			}
			cfg.PrivateKey = generatedPEM
			cfg.KeySource = "internal"
		} else {
			if keyProvidedInRequest {
				cfg.KeySource = "external"
			}
			key, err := parsePrivateKey(cfg.PrivateKey)
			if err != nil {
				return logical.ErrorResponse("invalid private_key: %s", err), nil
			}
			if err := validateKeyAlgorithmMatch(key, cfg.SigningAlgorithm); err != nil {
				return logical.ErrorResponse("%s", err), nil
			}
		}
		if cfg.PrivateKeyID == "" {
			kid, err := uuid.GenerateUUID()
			if err != nil {
				return nil, fmt.Errorf("failed to generate key ID: %w", err)
			}
			cfg.PrivateKeyID = kid
		}
		// Clear client_secret so stale sensitive material doesn't persist.
		cfg.ClientSecret = ""
	default:
		return logical.ErrorResponse("auth_method must be \"client_secret\" or \"private_key_jwt\""), nil
	}

	if verifyConnection, ok := d.Get("verify_connection").(bool); ok && verifyConnection {
		if err := verifyPingFederateConnection(ctx, cfg); err != nil {
			return logical.ErrorResponse("failed to verify connection to PingFederate: %s", err), nil
		}
	}

	entry, err := logical.StorageEntryJSON("config/"+name, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write config to storage: %w", err)
	}

	resp := &logical.Response{}
	resp.AddWarning("This plugin is currently in beta. Interfaces and behavior may change in future releases.")
	return resp, nil
}

func (b *pingFederateBackend) configDeleteOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.Get("name").(string)
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	// Check for dependent roles before deleting.
	var warnings []string

	if roleNames, err := req.Storage.List(ctx, "roles/"); err == nil {
		for _, roleName := range roleNames {
			role, err := getRole(ctx, req.Storage, roleName)
			if err != nil || role == nil {
				continue
			}
			if role.ConnectionName == name {
				warnings = append(warnings, fmt.Sprintf(
					"role %q references this connection and will stop working", roleName))
			}
		}
	}

	if staticRoleNames, err := req.Storage.List(ctx, "static-roles/"); err == nil {
		for _, roleName := range staticRoleNames {
			role, err := getStaticRole(ctx, req.Storage, roleName)
			if err != nil || role == nil {
				continue
			}
			if role.ConnectionName == name {
				warnings = append(warnings, fmt.Sprintf(
					"static role %q references this connection and will stop working", roleName))
			}
		}
	}

	if err := req.Storage.Delete(ctx, "config/"+name); err != nil {
		return nil, fmt.Errorf("failed to delete config from storage: %w", err)
	}

	b.resetConnection(name)

	if len(warnings) > 0 {
		resp := &logical.Response{}
		for _, w := range warnings {
			resp.AddWarning(w)
		}
		return resp, nil
	}

	return nil, nil
}

func (b *pingFederateBackend) configListOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	connections, err := req.Storage.List(ctx, "config/")
	if err != nil {
		return nil, fmt.Errorf("failed to list connections: %w", err)
	}

	return logical.ListResponse(connections), nil
}

// verifyPingFederateConnection attempts a client_credentials token request
// to validate that the configured credentials and token URL are correct.
func verifyPingFederateConnection(ctx context.Context, cfg *pingFederateConfig) error {
	httpClient := newHTTPClient(cfg.InsecureTLS)

	switch cfg.AuthMethod {
	case "", "client_secret":
		_, err := getAccessToken(ctx, httpClient, cfg.TokenURL, cfg.ClientID, cfg.ClientSecret)
		return err
	case "private_key_jwt":
		_, _, err := getBrokeredToken(ctx, httpClient, cfg, "", "", nil, nil)
		return err
	default:
		return fmt.Errorf("unsupported auth_method: %s", cfg.AuthMethod)
	}
}

func getConfig(ctx context.Context, s logical.Storage, name string) (*pingFederateConfig, error) {
	entry, err := s.Get(ctx, "config/"+name)
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
