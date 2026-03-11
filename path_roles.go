package pingfederate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type roleEntry struct {
	Name                string   `json:"name"`
	ConnectionName      string   `json:"connection_name"`
	DefaultScope        string   `json:"default_scope,omitempty"`
	AllowedScopes       []string `json:"allowed_scopes,omitempty"`
	AllowedMetadataKeys []string `json:"allowed_metadata_keys,omitempty"`
}

func pathRoles(b *pingFederateBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "ping-federate",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role.",
					Required:    true,
				},
				"connection_name": {
					Type:        framework.TypeString,
					Description: "Name of the connection to use for this role.",
					Required:    true,
				},
				"default_scope": {
					Type:        framework.TypeString,
					Description: "Default OAuth 2.0 scope for brokered token requests. Used when the caller does not specify a scope.",
				},
				"allowed_scopes": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Comma-separated list of permitted OAuth 2.0 scopes. If set, per-request scope values are validated against this list. If not set, any scope is allowed.",
				},
				"allowed_metadata_keys": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Comma-separated list of entity metadata keys to include as claims in token requests. If not set, all metadata keys are included (except reserved OAuth parameters).",
				},
			},
			ExistenceCheck: b.roleExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.roleReadOperation,
					Summary:  "Read a role.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "role",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback:                    b.roleWriteOperation,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
					Summary:                     "Create or update a role.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "role",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.roleWriteOperation,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
					Summary:                     "Create or update a role.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "role",
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback:                    b.roleDeleteOperation,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
					Summary:                     "Delete a role.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "role",
					},
				},
			},
			HelpSynopsis:    "Manage roles for PingFederate brokered token generation.",
			HelpDescription: "Create, read, update, or delete roles that control scope and metadata filtering for brokered tokens.",
		},
		{
			Pattern: "roles/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "ping-federate",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.roleListOperation,
					Summary:  "List roles.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "roles",
					},
				},
			},
			HelpSynopsis:    "List existing roles.",
			HelpDescription: "List existing roles by name.",
		},
	}
}

func (b *pingFederateBackend) roleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name, ok := d.Get("name").(string)
	if !ok {
		return false, nil
	}
	entry, err := req.Storage.Get(ctx, "roles/"+name)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *pingFederateBackend) roleReadOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.Get("name").(string)
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	data := map[string]any{
		"name":            role.Name,
		"connection_name": role.ConnectionName,
	}
	if role.DefaultScope != "" {
		data["default_scope"] = role.DefaultScope
	}
	if len(role.AllowedScopes) > 0 {
		data["allowed_scopes"] = role.AllowedScopes
	}
	if len(role.AllowedMetadataKeys) > 0 {
		data["allowed_metadata_keys"] = role.AllowedMetadataKeys
	}

	return &logical.Response{Data: data}, nil
}

func (b *pingFederateBackend) roleWriteOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.Get("name").(string)
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &roleEntry{Name: name}
	}

	if v, ok := d.GetOk("connection_name"); ok {
		role.ConnectionName, _ = v.(string)
	}
	if v, ok := d.GetOk("default_scope"); ok {
		role.DefaultScope, _ = v.(string)
	}
	if v, ok := d.GetOk("allowed_scopes"); ok {
		role.AllowedScopes, _ = v.([]string)
	}
	if v, ok := d.GetOk("allowed_metadata_keys"); ok {
		role.AllowedMetadataKeys, _ = v.([]string)
	}

	if role.ConnectionName == "" {
		return logical.ErrorResponse("connection_name is required"), nil
	}

	// Verify the referenced connection exists.
	cfg, err := getConfig(ctx, req.Storage, role.ConnectionName)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("connection %q does not exist", role.ConnectionName), nil
	}

	// Validate that default_scope values are a subset of allowed_scopes.
	if len(role.AllowedScopes) > 0 && role.DefaultScope != "" {
		allowed := make(map[string]bool, len(role.AllowedScopes))
		for _, s := range role.AllowedScopes {
			allowed[s] = true
		}
		for _, s := range strings.Fields(role.DefaultScope) {
			if !allowed[s] {
				return logical.ErrorResponse("default_scope contains %q which is not in allowed_scopes", s), nil
			}
		}
	}

	entry, err := logical.StorageEntryJSON("roles/"+name, role)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write role to storage: %w", err)
	}

	return nil, nil
}

func (b *pingFederateBackend) roleDeleteOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.Get("name").(string)
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	if err := req.Storage.Delete(ctx, "roles/"+name); err != nil {
		return nil, fmt.Errorf("failed to delete role from storage: %w", err)
	}

	return nil, nil
}

func (b *pingFederateBackend) roleListOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	return logical.ListResponse(roles), nil
}

func getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, fmt.Errorf("failed to read role from storage: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var role roleEntry
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, fmt.Errorf("failed to deserialize role: %w", err)
	}

	return &role, nil
}
