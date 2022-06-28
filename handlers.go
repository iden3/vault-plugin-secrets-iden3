package vault_plugin_secrets_bjj

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/wrapping"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-iden3-crypto/utils"
)

type backend struct {
	*framework.Backend
}

func handleMove(ctx context.Context, req *logical.Request,
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

func handleExistenceCheck(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (bool, error) {
	key := data.Get("path").(string)

	out, err := req.Storage.Get(ctx, key)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %v", err)
	}

	return out != nil, nil
}

func handleNewRandomKey(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	keyPath := data.Get(dataKeyPath).(string)
	if keyPath == "" {
		return nil, errors.New("key path is empty")
	}

	// Read the path
	out, err := req.Storage.Get(ctx, keyPath)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}
	if out != nil {
		return logical.ErrorResponse("key already exists"), nil
	}

	keyTp, err := newKeyTypeFromString(data.Get(dataKeyType).(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var privKey string
	switch keyTp {
	case keyTypeBJJ:
		privKey = randomBjjKey()
	case keyTypeEthereum:
		privKey, err = randomEthereumKey()
	default:
		return logical.ErrorResponse("unsupported key type"), nil
	}
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	extra := make(map[string]interface{})
	var obj = map[string]interface{}{
		privKeyMaterial: privKey,
		privKeyType:     keyTp.String(),
		extraData:       extra,
	}

	for k, v := range req.Data {
		if k == dataKeyType {
			continue
		}
		extra[k] = v
	}

	entry, err := logical.StorageEntryJSON(keyPath, obj)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %v", err)
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to write: %v", err)
	}

	return nil, nil
}

func handleImport(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	keyPath := data.Get(dataKeyPath).(string)
	if keyPath == "" {
		return nil, errors.New("key path is empty")
	}

	// Read the path
	out, err := req.Storage.Get(ctx, keyPath)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}
	if out != nil {
		return logical.ErrorResponse("key already exists"), nil
	}

	keyTp, err := newKeyTypeFromString(data.Get(dataKeyType).(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	keyMaterial, ok := data.Get(dataKeyPrivateKey).(string)
	if !ok {
		return nil, errors.New("private key is not found")
	}

	var privKey string
	switch keyTp {
	case keyTypeBJJ:
		privKey, err = normalizeBjjKey(keyMaterial)
	case keyTypeEthereum:
		privKey, err = normalizeEthereumKey(keyMaterial)
	default:
		return logical.ErrorResponse("unsupported key type"), nil
	}
	if err != nil {
		return logical.ErrorResponse(
			fmt.Sprintf("key check failed: %v", err.Error())), nil
	}

	extra := make(map[string]interface{})
	for k, v := range req.Data {
		if k == dataKeyType {
			continue
		}
		extra[k] = v
	}

	var obj = map[string]interface{}{
		privKeyMaterial: privKey,
		privKeyType:     keyTp.String(),
		extraData:       extra,
	}

	entry, err := logical.StorageEntryJSON(keyPath, obj)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %v", err)
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to write: %v", err)
	}

	return nil, nil
}

func handleSign(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	key := data.Get(dataKeyPath).(string)
	dataToSign := data.Get(dataKeyData).(string)

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

	pkStr, keyTp, err := extractKeyAndType(rawData)
	if err != nil {
		return nil, err
	}

	var signature string
	switch keyTp {
	case keyTypeBJJ:
		signature, err = signWithBJJ(pkStr, dataToSign)
	case keyTypeEthereum:
		signature, err = signWithETH(pkStr, dataToSign)
	default:
		return logical.ErrorResponse("unsupported key type"), nil
	}
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			dataKeySignature: signature,
			dataKeyData:      dataToSign,
		},
	}

	return resp, nil
}

func getReadHandler(showPrivate bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request,
		data *framework.FieldData) (*logical.Response, error) {

		key := data.Get("path").(string)

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

		privKeyStr, keyTp, err := extractKeyAndType(rawData)
		if err != nil {
			return nil, fmt.Errorf("unable to extract key and type: %v", err)
		}

		outData, ok := rawData[extraData].(map[string]interface{})
		if !ok {
			outData = make(map[string]interface{})
		}

		switch keyTp {
		case keyTypeBJJ:
			outData[dataKeyPublicKey], err = bjjPubKeyFromHex(privKeyStr)
		case keyTypeEthereum:
			outData[dataKeyPublicKey], err = ethPubKeyFromHex(privKeyStr)
		default:
			return logical.ErrorResponse("unsupported key type"), nil
		}
		if err != nil {
			return nil, err
		}

		outData[privKeyType] = keyTp.String()

		if showPrivate {
			outData[dataKeyPrivateKey] = rawData[privKeyMaterial]
		}

		resp := &logical.Response{Data: outData}

		// Ensure seal wrapping is carried through if the response is
		// response-wrapped
		if out.SealWrap {
			if resp.WrapInfo == nil {
				resp.WrapInfo = &wrapping.ResponseWrapInfo{}
			}
			resp.WrapInfo.SealWrap = out.SealWrap
		}

		return resp, nil
	}
}

func handleWrite(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	key := data.Get("path").(string)
	if key == "" {
		return logical.ErrorResponse("missing path"), nil
	}

	out, err := req.Storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if out == nil {
		return logical.ErrorResponse("key not found"), nil
	}

	var rawData map[string]interface{}

	if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
		return nil, fmt.Errorf("json decoding failed: %v", err)
	}

	// Check that some fields are given
	if len(req.Data) == 0 {
		delete(rawData, extraData)
		return logical.ErrorResponse("missing data fields"), nil
	} else {
		rawData[extraData] = req.Data
	}

	entry, err := logical.StorageEntryJSON(key, rawData)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write: %v", err)
	}

	return nil, nil
}

func handleDelete(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	key := data.Get("path").(string)

	// Delete the key at the request path
	if err := req.Storage.Delete(ctx, key); err != nil {
		return nil, err
	}

	return nil, nil
}

func handleList(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	// Right now we only handle directories, so ensure it ends with /; however,
	// some physical backends may not handle the "/" case properly, so only add
	// it if we're not listing the root
	path := data.Get("path").(string)
	if path != "" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	// List the keys at the prefix given by the request
	keys, err := req.Storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	// Generate the response
	return logical.ListResponse(keys), nil
}

func decodeBJJDigestData(digestHex string) (*big.Int, error) {
	digestBytes, err := hex.DecodeString(digestHex)
	if err != nil {
		return nil, fmt.Errorf("unable to decode digest from hex: %v", err)
	}
	i := new(big.Int).SetBytes(utils.SwapEndianness(digestBytes))
	if !utils.CheckBigIntInField(i) {
		return nil, errors.New("digest data is not inside Finite Field")
	}
	return new(big.Int).SetBytes(utils.SwapEndianness(digestBytes)), nil
}

type keyType uint8

func (t keyType) String() string {
	switch t {
	case keyTypeBJJ:
		return keyTypeBJJStr
	case keyTypeEthereum:
		return keyTypeEthereumStr
	default:
		return "unknown"
	}
}

const (
	keyTypeUnknown keyType = iota
	keyTypeBJJ
	keyTypeEthereum
)

const (
	keyTypeBJJStr      = "babyjubjub"
	keyTypeEthereumStr = "ethereum"
)

func newKeyTypeFromString(tp string) (keyType, error) {
	switch tp {
	case keyTypeBJJStr:
		return keyTypeBJJ, nil
	case keyTypeEthereumStr:
		return keyTypeEthereum, nil
	default:
		return keyTypeUnknown, errors.New("unknown key type")
	}
}

// hex representation of random BJJ key
func randomBjjKey() string {
	privKey := babyjub.NewRandPrivKey()
	return hex.EncodeToString(privKey[:])
}

// hex representation of random Ethereum key
func randomEthereumKey() (string, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.FromECDSA(key)), nil
}

func decodeBjjPrivKey(keyStr string) (babyjub.PrivateKey, error) {
	var key babyjub.PrivateKey
	privKeyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return key, err
	}

	if len(privKeyBytes) != len(key) {
		return key, errors.New("private key data length is incorrect")
	}

	copy(key[:], privKeyBytes)
	return key, nil
}

func decodeEthPrivKey(keyStr string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(keyStr)
}

func bjjPubKeyFromHex(keyStr string) (string, error) {
	key, err := decodeBjjPrivKey(keyStr)
	if err != nil {
		return "", err
	}
	pubKeyComp := key.Public().Compress()
	return hex.EncodeToString(pubKeyComp[:]), nil
}

func ethPubKeyFromHex(keyStr string) (string, error) {
	key, err := decodeEthPrivKey(keyStr)
	if err != nil {
		return "", err
	}

	pubKey, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("unable to convert private key to public key")
	}

	return hex.EncodeToString(crypto.FromECDSAPub(pubKey)), nil
}

func extractKeyAndType(data map[string]interface{}) (string, keyType, error) {
	pkStr, ok := data[privKeyMaterial].(string)
	if !ok {
		return "", keyTypeUnknown, fmt.Errorf("key material not found")
	}

	keyTpStr, ok := data[privKeyType].(string)
	if !ok {
		return "", keyTypeUnknown, fmt.Errorf("key type not found")
	}

	keyTp, err := newKeyTypeFromString(keyTpStr)
	if err != nil {
		return "", keyTypeUnknown, fmt.Errorf("invalid key type: %v", err)
	}

	return pkStr, keyTp, nil
}

func signWithBJJ(privKey string, dataToSign string) (string, error) {
	pKey, err := decodeBjjPrivKey(privKey)
	if err != nil {
		return "", err
	}

	digest, err := decodeBJJDigestData(dataToSign)
	if err != nil {
		return "", err
	}

	// If this function returns error, SignPoseidon would panic. So handle
	// this error here.
	_, err = poseidon.Hash([]*big.Int{digest})
	if err != nil {
		return "", fmt.Errorf("unable to sign with BJJ, hash error: %v", err)
	}
	sig := pKey.SignPoseidon(digest)
	sigComp := sig.Compress()
	return hex.EncodeToString(sigComp[:]), nil
}

func signWithETH(privKeyHex string, dataToSign string) (string, error) {
	privKey, err := decodeEthPrivKey(privKeyHex)
	if err != nil {
		return "", err
	}

	digest, err := hex.DecodeString(dataToSign)
	if err != nil {
		return "", fmt.Errorf(
			"unable to decode data to sign from hex string to bytes: %v", err)
	}
	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		return "", fmt.Errorf("unable to sign data with ethereum key: %v", err)
	}
	return hex.EncodeToString(sig), err
}

// take key hex string, try to convert it to BJJ private key, check for errors
// and convert to hex string back
func normalizeBjjKey(keyHex string) (string, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("unable to decode BJJ key from hex: %v", err)
	}
	if len(keyBytes) != len(babyjub.PrivateKey{}) {
		return "", fmt.Errorf("BJJ key data length is incorrect")
	}
	return hex.EncodeToString(keyBytes), nil
}

// take key hex string, try to convert it to Ethereum private key, check for
// errors and convert to hex string back
func normalizeEthereumKey(keyHex string) (string, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("unable to decode Ethereum key from hex: %v", err)
	}
	key, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return "",
			fmt.Errorf("unable to convert Ethereum key to ECDSA: %v", err)
	}
	keyBytes = crypto.FromECDSA(key)
	return hex.EncodeToString(keyBytes), nil
}
