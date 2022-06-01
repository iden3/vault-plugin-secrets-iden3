package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"

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
	dataKeyData      = "data"
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

				HelpSynopsis:    "TODO: help synopsis",    // TODO
				HelpDescription: "TODO: help description", // TODO
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
