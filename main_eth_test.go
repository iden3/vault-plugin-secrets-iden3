package vault_plugin_secrets_bjj_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

// create random key in vault and return path to it
func newRandomETHKey(t testing.TB, vaultCli *api.Client, kPath keyPath,
	extraData map[string]interface{}) {

	data := map[string]interface{}{
		"key_type": "ethereum",
	}
	for k, v := range extraData {
		data[k] = v
	}
	_, err := vaultCli.Logical().Write(kPath.new(), data)
	require.NoError(t, err)
}

func TestETHKeys(t *testing.T) {
	vaultCli, mountPath := newVaultClient(t)

	// register callback to delete key
	rmKey := func(keyPath string) {
		t.Cleanup(func() {
			_, err := vaultCli.Logical().Delete(keyPath)
			if err != nil {
				t.Error(err)
			}
		})
	}

	kPath := keyPath{mountPath: mountPath, keyPath: randomString()}
	newRandomETHKey(t, vaultCli, kPath,
		map[string]interface{}{"extra_key": "value"})
	rmKey(kPath.keys())

	publicSecData := dataAtPath(t, vaultCli, kPath.keys())
	privateSecData := dataAtPath(t, vaultCli, kPath.private())

	privKey, err := crypto.HexToECDSA(privateSecData["private_key"].(string))
	require.NoError(t, err)
	pubKey, ok := privKey.Public().(*ecdsa.PublicKey)
	require.True(t, ok)

	pubKeyBytes := crypto.FromECDSAPub(pubKey)
	privKeyBytes := crypto.FromECDSA(privKey)

	wantPublicData := map[string]interface{}{
		"key_type":   "ethereum",
		"public_key": hex.EncodeToString(pubKeyBytes),
		"extra_key":  "value",
	}
	require.Equal(t, wantPublicData, publicSecData)

	wantPrivateData := map[string]interface{}{
		"key_type":    "ethereum",
		"public_key":  hex.EncodeToString(pubKeyBytes),
		"private_key": hex.EncodeToString(privKeyBytes),
		"extra_key":   "value",
	}
	require.Equal(t, wantPrivateData, privateSecData)

	// Test sign
	h := common.Hash{}
	_, err = rand.Read(h[:])
	require.NoError(t, err)
	sig1, err := crypto.Sign(h[:], privKey)
	require.NoError(t, err)
	sig2 := signWithKey(vaultCli, kPath, h[:])
	require.Equal(t, sig1, sig2)

	// Test moving
	newKPath := keyPath{mountPath: mountPath, keyPath: randomString()}
	moveKey(vaultCli, kPath, newKPath)
	rmKey(newKPath.keys())
	newPublicSecData := dataAtPath(t, vaultCli, newKPath.keys())
	require.Equal(t, wantPublicData, newPublicSecData)
	newPrivateSecData := dataAtPath(t, vaultCli, newKPath.private())
	require.Equal(t, wantPrivateData, newPrivateSecData)

	require.Nil(t, dataAtPath(t, vaultCli, kPath.keys()))
}
