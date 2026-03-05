package pingfederate

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfig(_ *pingFederateBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields:  map[string]*framework.FieldSchema{},
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
		},
		HelpSynopsis:    "Configure the PingFederate connection.",
		HelpDescription: "Configure the PingFederate connection.",
	}
}

func configReadOperation(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func configWriteOperation(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
