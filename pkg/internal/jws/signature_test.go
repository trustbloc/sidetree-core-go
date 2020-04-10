/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/util"
)

func TestVerifySignature(t *testing.T) {
	t.Run("success P-256", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := util.GetECPublicKey(privateKey)
		require.NoError(t, err)

		payload := []byte("test")

		signature := getECSignature(privateKey, payload, crypto.SHA256)
		err = VerifySignature(jwk, signature, payload)
		require.NoError(t, err)
	})

	t.Run("success P-384", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		jwk, err := util.GetECPublicKey(privateKey)
		require.NoError(t, err)

		payload := []byte("test")

		signature := getECSignature(privateKey, payload, crypto.SHA384)
		err = VerifySignature(jwk, signature, payload)
		require.NoError(t, err)
	})

	t.Run("success P-521", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		jwk, err := util.GetECPublicKey(privateKey)
		require.NoError(t, err)

		payload := []byte("test")

		signature := getECSignature(privateKey, payload, crypto.SHA512)
		err = VerifySignature(jwk, signature, payload)
		require.NoError(t, err)
	})

	t.Run("unsupported key type", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := util.GetECPublicKey(privateKey)
		require.NoError(t, err)

		payload := []byte("test")
		signature := getECSignatureSHA256(privateKey, payload)

		jwk.Kty = "invalid"
		err = VerifySignature(jwk, signature, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported key type: invalid")
	})
}

func TestVerifyECSignature(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		jwk, err := util.GetECPublicKey(privateKey)
		require.NoError(t, err)

		payload := []byte("test")

		signature := getECSignatureSHA256(privateKey, payload)
		err = verifyECSignature(jwk, signature, payload)
		require.NoError(t, err)
	})
	t.Run("unsupported elliptic curve", func(t *testing.T) {
		jwk, err := util.GetECPublicKey(privateKey)
		require.NoError(t, err)

		payload := []byte("test")
		signature := getECSignatureSHA256(privateKey, payload)

		jwk.Crv = "invalid"
		err = verifyECSignature(jwk, signature, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported elliptic curve")
	})
	t.Run("invalid signature size", func(t *testing.T) {
		jwk, err := util.GetECPublicKey(privateKey)
		require.NoError(t, err)

		err = verifyECSignature(jwk, []byte("signature"), []byte("test"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature size")
	})
	t.Run("invalid signature", func(t *testing.T) {
		jwk, err := util.GetECPublicKey(privateKey)
		require.NoError(t, err)

		signature := getECSignatureSHA256(privateKey, []byte("test"))

		err = verifyECSignature(jwk, signature, []byte("different"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "ecdsa: invalid signature")
	})
}

func getECSignatureSHA256(privateKey *ecdsa.PrivateKey, payload []byte) []byte {
	return getECSignature(privateKey, payload, crypto.SHA256)
}

func getECSignature(privKey *ecdsa.PrivateKey, payload []byte, hash crypto.Hash) []byte {
	hasher := hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		panic(err)
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashed)
	if err != nil {
		panic(err)
	}

	curveBits := privKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	copyPadded := func(source []byte, size int) []byte {
		dest := make([]byte, size)
		copy(dest[size-len(source):], source)

		return dest
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...)
}
