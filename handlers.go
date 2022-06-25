package vault_plugin_secrets_bjj

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/utils"
)

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
			return logical.ErrorResponse("key already exists"), nil
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

func decodeDigestData(digestHex string) (*big.Int, error) {
	digestBytes, err := hex.DecodeString(digestHex)
	if err != nil {
		return nil, fmt.Errorf("unable to decode digest from hex: %v", err)
	}
	return new(big.Int).SetBytes(utils.SwapEndianness(digestBytes)), nil
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
