package vault_plugin_secrets_bjj

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/require"
)

const (
	keyDest      = "dest"
	keyPublicKey = "public_key"
	keyData      = "data"
	keySignature = "signature"
)

func newVaultClient(t testing.TB) (vaultCli *api.Client, mountPath string) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		t.Skip("vault address is not configured")
	}
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		t.Skip("vault token is not configured")
	}

	mountPath = os.Getenv("VAULT_BJJ_PATH")
	if mountPath == "" {
		t.Skip("BJJ plugin mount path is not set")
	}

	config := api.DefaultConfig()
	config.Address = vaultAddr

	var err error
	vaultCli, err = api.NewClient(config)
	require.NoError(t, err)

	vaultCli.SetToken(vaultToken)

	return
}

// create random key in vault and return path to it
func newRandomBJJKey(t testing.TB, vaultCli *api.Client, keyPath string,
	extraData map[string]interface{}) {

	rndKeyPath := path.Join(keyPath, "random")
	_, err := vaultCli.Logical().Write(rndKeyPath, extraData)
	require.NoError(t, err)
}

func getSecretData(secret *api.Secret) map[string]interface{} {
	if secret == nil {
		panic("secret is nil")
	}

	if secret.Data == nil {
		panic("secret data is nil")
	}

	return secret.Data
}

func getPublicKey(t testing.TB, vaultCli *api.Client, keyPath string) string {
	requestPath := path.Join(keyPath, "public")
	secret, err := vaultCli.Logical().Read(requestPath)
	if err != nil {
		panic(err)
	}

	data := getSecretData(secret)

	pubKeyStr, ok := data[keyPublicKey].(string)
	if !ok {
		panic("unable to get public key from secret")
	}

	return pubKeyStr
}

func randomKeyPath(basePath string) string {
	var rnd [16]byte
	_, err := rand.Read(rnd[:])
	if err != nil {
		panic(err)
	}

	return path.Join(basePath, hex.EncodeToString(rnd[:]))
}

// move bjj key under new path
func signBJJKey(vaultCli *api.Client, keyPath string,
	dataToSign []byte) []byte {

	dataStr := hex.EncodeToString(dataToSign)
	data := map[string][]string{keyData: {dataStr}}
	requestPath := path.Join(keyPath, "sign")
	secret, err := vaultCli.Logical().ReadWithData(requestPath, data)
	if err != nil {
		panic(err)
	}
	data2 := getSecretData(secret)
	sigStr, ok := data2[keySignature].(string)
	if !ok {
		panic("unable to get signature from secret")
	}
	sig, err := hex.DecodeString(sigStr)
	if err != nil {
		panic(err)
	}
	return sig
}

// move bjj key under new path
func moveBJJKey(vaultCli *api.Client, oldPath, newPath string) {
	data := map[string]interface{}{keyDest: newPath}
	requestPath := path.Join(oldPath, "move")
	_, err := vaultCli.Logical().Write(requestPath, data)
	if err != nil {
		panic(err)
	}
}

func dataAtPath(t testing.TB, vaultCli *api.Client,
	keyPath string) map[string]interface{} {

	secret, err := vaultCli.Logical().Read(keyPath)
	require.NoError(t, err)
	if secret == nil {
		return nil
	}
	return getSecretData(secret)
}

func TestBJJPlugin(t *testing.T) {
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

	keyPath := randomKeyPath(mountPath)
	newRandomBJJKey(t, vaultCli, keyPath,
		map[string]interface{}{"extra_key": "value"})
	rmKey(keyPath)

	secData := dataAtPath(t, vaultCli, keyPath)
	require.Equal(t, "value", secData["extra_key"])

	var privKey babyjub.PrivateKey
	privKeyStr, err := hex.DecodeString(secData["key_data"].(string))
	require.NoError(t, err)
	copy(privKey[:], privKeyStr)
	pubKey1Comp := privKey.Public().Compress()

	pubKey2Str := getPublicKey(t, vaultCli, keyPath)
	var pubKey2Comp babyjub.PublicKeyComp
	pubKey2Bytes, err := hex.DecodeString(pubKey2Str)
	require.NoError(t, err)
	copy(pubKey2Comp[:], pubKey2Bytes)

	require.Equal(t, pubKey1Comp, pubKey2Comp)

	// Test sign
	nonce := big.NewInt(100500)
	nonceBytes := utils.SwapEndianness(nonce.Bytes())
	sig1 := privKey.SignPoseidon(nonce).Compress()
	sig2Bytes := signBJJKey(vaultCli, keyPath, nonceBytes)
	var sig2 babyjub.SignatureComp
	copy(sig2[:], sig2Bytes)
	require.Equal(t, sig1, sig2)

	// Test moving
	newKeyPath := randomKeyPath(mountPath)
	moveBJJKey(vaultCli, keyPath, newKeyPath)
	newSecData := dataAtPath(t, vaultCli, newKeyPath)
	require.Equal(t, secData, newSecData)

	require.Nil(t, dataAtPath(t, vaultCli, keyPath))
}
