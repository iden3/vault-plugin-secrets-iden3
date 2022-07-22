package main

import (
	"encoding/hex"
	"testing"

	"github.com/iden3/go-iden3-crypto/babyjub"
)

func TestRnd(t *testing.T) {
	t.Skip("generate random key for testing")
	key := babyjub.NewRandPrivKey()
	t.Logf("key: %s", hex.EncodeToString(key[:]))
	pub := key.Public()
	pubComp := pub.Compress()
	t.Logf("public: %s", hex.EncodeToString(pubComp[:]))
}
