/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecsigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	msg := []byte("test message")

	t.Run("success EC P-256", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := New(privateKey, "ES256", "key-1")

		signature, err := signer.Sign(msg)
		require.NoError(t, err)
		require.NotEmpty(t, signature)
	})

	t.Run("success EC P-384", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		signer := New(privateKey, "ES384", "key-1")

		signature, err := signer.Sign(msg)
		require.NoError(t, err)
		require.NotEmpty(t, signature)
	})

	t.Run("success EC P-521", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		signer := New(privateKey, "ES521", "key-1")

		signature, err := signer.Sign(msg)
		require.NoError(t, err)
		require.NotEmpty(t, signature)
	})

	t.Run("success EC secp256k1 ", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		require.NoError(t, err)

		signer := New(privateKey, "ES256K", "key-1")

		signature, err := signer.Sign(msg)
		require.NoError(t, err)
		require.NotEmpty(t, signature)
	})

	t.Run("private key not provided", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		require.NoError(t, err)

		signer := New(privateKey, "ES256K", "key-1")
		signer.privateKey = nil

		signature, err := signer.Sign(msg)
		require.Error(t, err)
		require.Nil(t, signature)
		require.Contains(t, err.Error(), "private key not provided")
	})
}

func TestHeaders(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("success - kid, alg provided", func(t *testing.T) {
		signer := New(privateKey, "ES256", "key-1")

		// verify headers
		kid, ok := signer.Headers().KeyID()
		require.Equal(t, true, ok)
		require.Equal(t, "key-1", kid)

		alg, ok := signer.Headers().Algorithm()
		require.Equal(t, true, ok)
		require.Equal(t, "ES256", alg)
	})

	t.Run("success - kid, alg not provided", func(t *testing.T) {
		signer := New(privateKey, "", "")

		// verify headers
		kid, ok := signer.Headers().KeyID()
		require.Equal(t, false, ok)
		require.Empty(t, kid)

		alg, ok := signer.Headers().Algorithm()
		require.Equal(t, false, ok)
		require.Empty(t, alg)
	})
}
