package vault_plugin_secrets_bjj

import (
	"context"

	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	dataKeyPath      = "path"
	dataKeyDest      = "dest"
	dataKeyData      = "data"
	dataKeyPublicKey = "public_key"
	dataKeyKey       = "key"
	dataKeySignature = "signature"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend,
	error) {
	var b logical.Backend
	var err error
	b, err = kv.PassthroughBackendFactory(ctx, conf)
	if err != nil {
		return nil, err
	}

	pb := b.(*kv.PassthroughBackend)
	pb.Paths = append(
		[]*framework.Path{
			{
				Pattern: `(?P<path>.*)/sign`,

				Fields: map[string]*framework.FieldSchema{
					dataKeyPath: {
						Type:        framework.TypeString,
						Description: "Location of the secret.",
					},
					dataKeyData: {
						Type: framework.TypeString,
						Description: "Data to sign. Hex representation of " +
							"little endian encoded int.",
						Required: true,
					},
					dataKeyKey: {
						Type: framework.TypeString,
						Description: "Key name under which private key is " +
							"stored.",
						Required: true,
						Default:  "key_data",
					},
				},

				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: handleSign(pb),
					},
				},

				ExistenceCheck: handleExistenceCheck(),

				HelpSynopsis:    "Sign integer with BabyJubJub key",
				HelpDescription: "",
			},
			{
				Pattern: `(?P<path>.*)/move`,
				Fields: map[string]*framework.FieldSchema{
					dataKeyPath: {
						Type:        framework.TypeString,
						Description: "Location of the secret.",
					},
					dataKeyDest: {
						Type:        framework.TypeString,
						Description: "New location of the secret.",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.CreateOperation: &framework.PathOperation{
						Callback: handleMove(),
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback: handleMove(),
					},
				},
				ExistenceCheck:  handleExistenceCheck(),
				HelpSynopsis:    "Move to other path",
				HelpDescription: "",
			},
			{
				Pattern: `(?P<path>.*)/public`,

				Fields: map[string]*framework.FieldSchema{
					dataKeyPath: {
						Type:        framework.TypeString,
						Description: "Location of the secret.",
					},
					dataKeyKey: {
						Type: framework.TypeString,
						Description: "Key name under which private key is " +
							"stored.",
						Required: true,
						Default:  "key_data",
					},
				},

				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: handlePublicKey(),
					},
				},

				ExistenceCheck: handleExistenceCheck(),

				HelpSynopsis: "Public Key for BabyJubJub private key",
				HelpDescription: "Return hex encoded compressed public key " +
					"for BabyJubJub private key",
			},
			{
				Pattern: `(?P<path>.*)/random`,

				Fields: map[string]*framework.FieldSchema{
					dataKeyPath: {
						Type:        framework.TypeString,
						Description: "Location of the secret.",
					},
					dataKeyKey: {
						Type: framework.TypeString,
						Description: "Key name under which private key is " +
							"stored.",
						Required: true,
						Default:  "key_data",
					},
				},

				Operations: map[logical.Operation]framework.OperationHandler{
					logical.CreateOperation: &framework.PathOperation{
						Callback: handleNewRandomKey(),
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback: handleNewRandomKey(),
					},
				},

				ExistenceCheck: handleExistenceCheck(),

				HelpSynopsis:    "Create new random BabyJubJub private key",
				HelpDescription: "",
			},
		},
		pb.Paths...)

	return b, nil
}
