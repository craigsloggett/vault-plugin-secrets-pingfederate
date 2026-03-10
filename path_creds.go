package pingfederate

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreds(b *pingFederateBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "ping-federate",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
				Required:    true,
			},
			"scope": {
				Type:        framework.TypeString,
				Description: "OAuth 2.0 scope to request. If omitted, the role's default_scope is used.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.credsReadOperation,
				Summary:  "Obtain a brokered token from PingFederate enriched with the caller's Vault identity.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "brokered-token",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.credsReadOperation,
				Summary:  "Obtain a brokered token from PingFederate enriched with the caller's Vault identity.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "brokered-token",
				},
			},
		},
		HelpSynopsis:    "Obtain a brokered access token from PingFederate.",
		HelpDescription: "Authenticates to PingFederate's token endpoint as the foothold client, enriching the request with the caller's Vault entity ID and metadata. Returns a JWT access token.",
	}
}

func (b *pingFederateBackend) credsReadOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.EntityID == "" {
		return logical.ErrorResponse("this endpoint requires an authenticated caller with a Vault identity entity"), nil
	}

	name, ok := d.Get("name").(string)
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", name), nil
	}

	cfg, err := getConfig(ctx, req.Storage, role.ConnectionName)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("connection %q not configured", role.ConnectionName), nil
	}

	client, err := b.getClientForConnection(ctx, req.Storage, role.ConnectionName)
	if err != nil {
		return nil, err
	}

	entity, err := b.System().EntityInfo(req.EntityID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up entity %s: %w", req.EntityID, err)
	}

	var metadata map[string]string
	if entity != nil {
		metadata = entity.Metadata
	}

	scope, _ := d.Get("scope").(string)

	if scope == "" && role.DefaultScope != "" {
		scope = role.DefaultScope
	}

	if scope != "" && len(role.AllowedScopes) > 0 {
		allowed := make(map[string]bool, len(role.AllowedScopes))
		for _, s := range role.AllowedScopes {
			allowed[s] = true
		}
		for _, s := range strings.Fields(scope) {
			if !allowed[s] {
				return logical.ErrorResponse("scope %q is not in allowed_scopes", s), nil
			}
		}
	}

	tokenResp, skippedKeys, err := getBrokeredToken(ctx, client.HTTPClient(), cfg, scope, req.EntityID, metadata, role.AllowedMetadataKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain brokered token: %w", err)
	}

	resp := &logical.Response{
		Data: map[string]any{
			"access_token": tokenResp.AccessToken,
			"token_type":   tokenResp.TokenType,
			"expires_in":   tokenResp.ExpiresIn,
		},
	}
	for _, k := range skippedKeys {
		resp.AddWarning(fmt.Sprintf("Entity metadata key %q conflicts with a reserved OAuth parameter and was not sent to PingFederate.", k))
	}
	resp.AddWarning("This plugin is currently in beta. Interfaces and behavior may change in future releases.")
	return resp, nil
}
