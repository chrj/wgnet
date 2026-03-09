package wgnet

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

type Key [32]byte

func RandomKey() Key {
	var b = make([]byte, 32)
	var k Key
	rand.Read(b)
	copy(k[:], b)
	// https://cr.yp.to/ecdh.html
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}

func (k Key) Private() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k Key) Public() string {
	var pub [32]byte
	var priv = [32]byte(k)
	curve25519.ScalarBaseMult(&pub, &priv)
	return base64.StdEncoding.EncodeToString(pub[:])
}

func b64tohex(in string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return "", fmt.Errorf("unable to decode base64: %v", err)
	}

	if len(bytes) != 32 {
		return "", fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(bytes))
	}

	return hex.EncodeToString(bytes), nil
}
