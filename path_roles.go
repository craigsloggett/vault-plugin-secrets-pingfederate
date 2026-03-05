package pingfederate

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRoles(_ *pingFederateBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role.",
					Required:    true,
				},
			},
			ExistenceCheck: roleExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: roleReadOperation,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: roleWriteOperation,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: roleWriteOperation,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: roleDeleteOperation,
				},
			},
			HelpSynopsis:    "Manage roles for PingFederate credential generation.",
			HelpDescription: "Manage roles for PingFederate credential generation.",
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: roleListOperation,
				},
			},
			HelpSynopsis:    "List existing roles.",
			HelpDescription: "List existing roles.",
		},
	}
}

func roleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
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

func roleReadOperation(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func roleWriteOperation(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func roleDeleteOperation(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func roleListOperation(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
