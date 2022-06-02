package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

const (
	dataKeyPath      = "path"
	dataKeyDest      = "dest"
	dataKeyData      = "data"
	dataKeyPublicKey = "public_key"
	dataKeyKey       = "key"
	dataKeySignature = "signature"
)

func handleExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context,
		req *logical.Request,
		data *framework.FieldData) (bool, error) {
		key := data.Get("path").(string)

		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return false, fmt.Errorf("existence check failed: %v", err)
		}

		return out != nil, nil
	}
}

func decodePrivateKey(rawData map[string]interface{},
	key string) (babyjub.PrivateKey, error) {

	var pKey babyjub.PrivateKey

	pkDataI, ok := rawData[key]
	if !ok {
		return pKey, fmt.Errorf("private key not found under key %v", key)
	}
	pkData, ok := pkDataI.(string)
	if !ok {
		return pKey, errors.New("private key data is not a string")
	}

	if len(pkData) != len(pKey)*2 {
		return pKey, errors.New("private key data length is incorrect")
	}
	_, err := hex.Decode(pKey[:], []byte(pkData))
	if err != nil {
		return pKey,
			fmt.Errorf("unable to decode private key from hex: %v", err)
	}

	return pKey, nil
}

func decodeDigestData(digestHex string) (*big.Int, error) {

	digestBytes, err := hex.DecodeString(digestHex)
	if err != nil {
		return nil, fmt.Errorf("unable to decode digest from hex: %v", err)
	}

	return new(big.Int).SetBytes(digestBytes), nil
}

func handleSign(b *kv.PassthroughBackend) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request,
		data *framework.FieldData) (*logical.Response, error) {

		key := data.Get(dataKeyPath).(string)
		dataToSign := data.Get(dataKeyData).(string)
		pkKey := data.Get(dataKeyKey).(string)

		b.Logger().Debug("handle sign", "path", key)

		// Read the path
		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("read failed: %v", err)
		}

		// Fast-path the no data case
		if out == nil {
			return nil, nil
		}

		// Decode the data
		var rawData map[string]interface{}

		if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
			return nil, fmt.Errorf("json decoding failed: %v", err)
		}

		pKey, err := decodePrivateKey(rawData, pkKey)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		digest, err := decodeDigestData(dataToSign)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		sig := pKey.SignPoseidon(digest)
		sigComp := sig.Compress()

		var resp *logical.Response
		resp = &logical.Response{
			Data: map[string]interface{}{
				dataKeySignature: hex.EncodeToString(sigComp[:]),
				dataKeyData:      dataToSign,
			},
		}

		return resp, nil
	}
}

func handleMove() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request,
		data *framework.FieldData) (*logical.Response, error) {

		key := data.Get(dataKeyPath).(string)
		destKey := data.Get(dataKeyDest).(string)

		destKey = strings.TrimPrefix(destKey, "/")

		if !strings.HasPrefix(destKey, req.MountPoint) {
			return nil, fmt.Errorf(
				"destination key must be in the same mount point |%v|%v|",
				req.MountPoint, destKey)
		}

		destKey = strings.TrimPrefix(destKey, req.MountPoint)

		// Read the path
		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("read failed: %v", err)
		}

		// Fast-path the no data case
		if out == nil {
			return nil, nil
		}

		err = req.Storage.Put(ctx, &logical.StorageEntry{
			Key:      destKey,
			Value:    out.Value,
			SealWrap: out.SealWrap,
		})
		if err != nil {
			return nil, fmt.Errorf("write failed: %v", err)
		}

		err = req.Storage.Delete(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("delete failed: %v", err)
		}

		return nil, nil
	}
}

func handlePublicKey() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request,
		data *framework.FieldData) (*logical.Response, error) {

		key := data.Get(dataKeyPath).(string)
		pkKey := data.Get(dataKeyKey).(string)

		// Read the path
		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("read failed: %v", err)
		}

		// Fast-path the no data case
		if out == nil {
			return nil, nil
		}

		// Decode the data
		var rawData map[string]interface{}

		if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
			return nil, fmt.Errorf("json decoding failed: %v", err)
		}

		pKey, err := decodePrivateKey(rawData, pkKey)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		pubKeyComp := pKey.Public().Compress()

		var resp *logical.Response
		resp = &logical.Response{
			Data: map[string]interface{}{
				dataKeyPublicKey: hex.EncodeToString(pubKeyComp[:]),
			},
		}

		return resp, nil
	}
}

func handleNewRandomKey() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request,
		data *framework.FieldData) (*logical.Response, error) {

		key := data.Get(dataKeyPath).(string)
		privKeyFieldName := data.Get(dataKeyKey).(string)
		if privKeyFieldName == "" {
			return nil, errors.New("private key field name is required")
		}

		// Read the path
		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("read failed: %v", err)
		}
		if out != nil {
			return nil, fmt.Errorf("key already exists")
		}

		privKey := babyjub.NewRandPrivKey()
		var obj = map[string]interface{}{
			privKeyFieldName: hex.EncodeToString(privKey[:]),
		}

		for k, v := range req.Data {
			if k == privKeyFieldName {
				return nil, errors.New("extra data has a field conflicting " +
					"with private key field name")
			}
			if k == dataKeyKey {
				continue
			}
			obj[k] = v
		}

		entry := &logical.StorageEntry{Key: key}
		entry.Value, err = json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("json encoding failed: %v", err)
		}

		err = req.Storage.Put(ctx, entry)
		if err != nil {
			return nil, fmt.Errorf("failed to write: %v", err)
		}

		return nil, nil
	}
}

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

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
