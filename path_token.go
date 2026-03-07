package pingfederate

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathToken(b *pingFederateBackend) *framework.Path {
	return &framework.Path{
		Pattern: "token",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "ping-federate",
		},
		Fields: map[string]*framework.FieldSchema{
			"scope": {
				Type:        framework.TypeString,
				Description: "OAuth 2.0 scope to request. If omitted, PingFederate uses the client's default scope.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.tokenReadOperation,
				Summary:  "Obtain a brokered token from PingFederate enriched with the caller's Vault identity.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "brokered-token",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.tokenReadOperation,
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

func (b *pingFederateBackend) tokenReadOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.EntityID == "" {
		return logical.ErrorResponse("this endpoint requires an authenticated caller with a Vault identity entity"), nil
	}

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("backend not configured"), nil
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

	tokenResp, skippedKeys, err := getBrokeredToken(ctx, newHTTPClient(cfg.InsecureTLS), cfg, scope, req.EntityID, metadata)
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
