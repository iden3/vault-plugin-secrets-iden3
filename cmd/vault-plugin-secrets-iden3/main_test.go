package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"os"
	"path"
	"strings"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/stretchr/testify/require"
)

var runVaultAPI *bool

func init() {
	runVaultAPI = flag.Bool("vault", false, "Run series of tests against Vault API")
}

func rndKeyName(t testing.TB) string {
	ln := 10
	n := make([]byte, ln)
	l, err := rand.Read(n)
	require.NoError(t, err)
	require.Equal(t, ln, l)
	return hex.EncodeToString(n)
}

func env(t testing.TB, envName string) string {
	val, ok := os.LookupEnv(envName)
	if !ok || val == "" {
		t.Fatalf("%s is not set", envName)
	}
	return val
}

func vaultCli(t testing.TB) *vault.Client {
	vaultAddr := env(t, "VAULT_ADDR")
	vaultToken := env(t, "VAULT_TOKEN")

	cfg := vault.DefaultConfig()
	cfg.Address = vaultAddr
	client, err := vault.NewClient(cfg)
	require.NoError(t, err)
	client.SetToken(vaultToken)
	return client
}

func TestRnd(t *testing.T) {
	t.Skip("generate random key for testing")
	key := babyjub.NewRandPrivKey()
	t.Logf("key: %s", hex.EncodeToString(key[:]))
	pub := key.Public()
	pubComp := pub.Compress()
	t.Logf("public: %s", hex.EncodeToString(pubComp[:]))
}

func TestVaultPlugin(t *testing.T) {
	if !*runVaultAPI {
		t.Skip("set -vault flag to run this test")
	}

	vaultIden3 := env(t, "VAULT_IDEN3_PATH")
	vaultIden3 = strings.TrimSuffix(vaultIden3, "/")

	cfg := vault.DefaultConfig()
	cfg.Address = "http://127.0.0.1:8200"
	client := vaultCli(t)
	l := client.Logical()

	t.Run("check mount exists", func(t *testing.T) {
		sys := client.Sys()
		mounts, err := sys.ListMounts()
		require.NoError(t, err)
		var iden3Found bool
		for k, v := range mounts {
			if strings.TrimSuffix(k, "/") == vaultIden3 {
				require.Equal(t, "vault-plugin-secrets-iden3", v.Type)
				iden3Found = true
				break
			}
		}
		require.True(t, iden3Found, "Iden3 plugin mount is not found")
	})

	require.False(t, t.Failed(), "mount check failed, no point to continue")

	keyName := rndKeyName(t)

	t.Run("create new key", func(t *testing.T) {
		p := path.Join(vaultIden3, "new", keyName)
		s, err := l.Write(p, map[string]interface{}{"key_type": "babyjubjub"})
		require.NoError(t, err)
		require.Nil(t, s)
	})

	require.False(t, t.Failed(), "create new key failed, no point to continue")

	t.Run("list keys", func(t *testing.T) {
		p := path.Join(vaultIden3, "keys")
		s, err := l.List(p)
		require.NoError(t, err)
		require.NotNil(t, s)
		require.NotNil(t, s.Data)
		keys, ok := s.Data["keys"].([]any)
		require.Truef(t, ok, "keys is not a list: %T", s.Data["keys"])
		var found bool
		for _, k := range keys {
			k2, ok := k.(string)
			if !ok {
				continue
			}
			if k2 == keyName {
				found = true
				break
			}
		}
		require.Truef(t, found, "key not found in the list: %v", keyName)
	})

	t.Run("read key data", func(t *testing.T) {
		p := path.Join(vaultIden3, "keys", keyName)
		s, err := l.Read(p)
		require.NoError(t, err)
		require.NotNil(t, s)
		require.NotNil(t, s.Data)
		require.Equal(t, "babyjubjub", s.Data["key_type"])
		require.NotEmpty(t, s.Data["public_key"])
	})

	t.Run("delete key", func(t *testing.T) {
		p := path.Join(vaultIden3, "keys", keyName)
		_, err := l.Delete(p)
		require.NoError(t, err)
	})

	t.Run("list keys after delete", func(t *testing.T) {
		p := path.Join(vaultIden3, "keys")
		s, err := l.List(p)
		require.NoError(t, err)
		require.NotNil(t, s)
		require.NotNil(t, s.Data)
		keys, ok := s.Data["keys"].([]any)
		require.Truef(t, ok, "keys is not a list: %T", s.Data["keys"])
		var found bool
		for _, k := range keys {
			k2, ok := k.(string)
			if !ok {
				continue
			}
			if k2 == keyName {
				found = true
				break
			}
		}
		require.Falsef(t, found, "key exists after delete: %v", keyName)
	})
}
