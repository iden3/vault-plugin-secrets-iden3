package vault_plugin_secrets_bjj_test

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
func newRandomBJJKey(t testing.TB, vaultCli *api.Client, kPath keyPath,
	extraData map[string]interface{}) {

	data := map[string]interface{}{
		"key_type": "babyjubjub",
	}
	for k, v := range extraData {
		data[k] = v
	}
	_, err := vaultCli.Logical().Write(kPath.new(), data)
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

func randomString() string {
	var rnd [16]byte
	_, err := rand.Read(rnd[:])
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(rnd[:])
}

// move bjj key under new path
func signBJJKey(vaultCli *api.Client, kPath keyPath, dataToSign []byte) []byte {
	dataStr := hex.EncodeToString(dataToSign)
	data := map[string][]string{"data": {dataStr}}
	secret, err := vaultCli.Logical().ReadWithData(kPath.sign(), data)
	if err != nil {
		panic(err)
	}
	data2 := getSecretData(secret)
	sigStr, ok := data2["signature"].(string)
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
func moveBJJKey(vaultCli *api.Client, oldPath, newPath keyPath) {
	data := map[string]interface{}{"dest": newPath.keys()}
	_, err := vaultCli.Logical().Write(oldPath.move(), data)
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

type keyPath struct {
	mountPath string
	keyPath   string
}

func (p keyPath) insert(verb string) string {
	return path.Join(p.mountPath, verb, p.keyPath)
}

func (p keyPath) new() string {
	return p.insert("new")
}

func (p keyPath) keys() string {
	return p.insert("keys")
}

func (p keyPath) private() string {
	return p.insert("private")
}

func (p keyPath) sign() string {
	return p.insert("sign")
}

func (p keyPath) move() string {
	return p.insert("move")
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

	kPath := keyPath{mountPath: mountPath, keyPath: randomString()}
	newRandomBJJKey(t, vaultCli, kPath,
		map[string]interface{}{"extra_key": "value"})
	rmKey(kPath.keys())

	publicSecData := dataAtPath(t, vaultCli, kPath.keys())
	privateSecData := dataAtPath(t, vaultCli, kPath.private())

	var privKey babyjub.PrivateKey
	privKeyStr, err := hex.DecodeString(privateSecData["private_key"].(string))
	require.NoError(t, err)
	copy(privKey[:], privKeyStr)
	pubKey1Comp := privKey.Public().Compress()

	wantPublicData := map[string]interface{}{
		"key_type":   "babyjubjub",
		"public_key": hex.EncodeToString(pubKey1Comp[:]),
		"extra_key":  "value",
	}
	require.Equal(t, wantPublicData, publicSecData)

	wantPrivateData := map[string]interface{}{
		"key_type":    "babyjubjub",
		"public_key":  hex.EncodeToString(pubKey1Comp[:]),
		"private_key": hex.EncodeToString(privKey[:]),
		"extra_key":   "value",
	}
	require.Equal(t, wantPrivateData, privateSecData)

	// Test sign
	nonce := big.NewInt(100500)
	nonceBytes := utils.SwapEndianness(nonce.Bytes())
	sig1 := privKey.SignPoseidon(nonce).Compress()
	sig2Bytes := signBJJKey(vaultCli, kPath, nonceBytes)
	var sig2 babyjub.SignatureComp
	copy(sig2[:], sig2Bytes)
	require.Equal(t, sig1, sig2)

	// Test moving
	newKPath := keyPath{mountPath: mountPath, keyPath: randomString()}
	moveBJJKey(vaultCli, kPath, newKPath)
	rmKey(newKPath.keys())
	newPublicSecData := dataAtPath(t, vaultCli, newKPath.keys())
	require.Equal(t, wantPublicData, newPublicSecData)
	newPrivateSecData := dataAtPath(t, vaultCli, newKPath.private())
	require.Equal(t, wantPrivateData, newPrivateSecData)

	require.Nil(t, dataAtPath(t, vaultCli, kPath.keys()))
}
