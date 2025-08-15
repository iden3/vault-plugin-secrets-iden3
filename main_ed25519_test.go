package vault_plugin_secrets_bjj_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func newRandomEd25519Key(t testing.TB, vaultCli *api.Client, kPath keyPath,
	extraData map[string]interface{}) {

	data := map[string]interface{}{
		"key_type": "ed25519",
	}
	for k, v := range extraData {
		data[k] = v
	}
	_, err := vaultCli.Logical().Write(kPath.new(), data)
	require.NoError(t, err)
}

func TestEd25519Keys(t *testing.T) {
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
	newRandomEd25519Key(t, vaultCli, kPath,
		map[string]interface{}{"extra_key": "value"})
	rmKey(kPath.keys())

	publicSecData := dataAtPath(t, vaultCli, kPath.keys())
	privateSecData := dataAtPath(t, vaultCli, kPath.private())

	privKeyData, err := hex.DecodeString(privateSecData["private_key"].(string))
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyData)
	pubKey, ok := privKey.Public().(ed25519.PublicKey)
	require.True(t, ok)

	wantPublicData := map[string]interface{}{
		"key_type":   "ed25519",
		"public_key": hex.EncodeToString(pubKey),
		"extra_key":  "value",
	}
	require.Equal(t, wantPublicData, publicSecData)

	wantPrivateData := map[string]interface{}{
		"key_type":    "ed25519",
		"public_key":  hex.EncodeToString(pubKey),
		"private_key": hex.EncodeToString(privKey),
		"extra_key":   "value",
	}
	require.Equal(t, wantPrivateData, privateSecData)

	// Test sign
	h := common.Hash{}
	_, err = rand.Read(h[:])
	require.NoError(t, err)
	sig1 := ed25519.Sign(privKey, h[:])
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
