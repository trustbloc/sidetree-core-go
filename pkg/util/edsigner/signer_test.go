/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edsigner

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msg := []byte("test message")

	t.Run("success", func(t *testing.T) {
		signer := New(privateKey, "EdDSA", "key-1")

		signature, err := signer.Sign(msg)
		require.NoError(t, err)
		require.NotEmpty(t, signature)
	})

	t.Run("invalid key size", func(t *testing.T) {
		signer := New(privateKey, "EdDSA", "key-1")
		signer.privateKey = nil

		signature, err := signer.Sign(msg)
		require.Error(t, err)
		require.Nil(t, signature)
		require.Contains(t, err.Error(), "invalid private key size")
	})
}

func TestHeaders(t *testing.T) {
	t.Run("success - kid, alg provided", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signer := New(privateKey, "EdDSA", "key-1")

		// verify headers
		kid, ok := signer.Headers().KeyID()
		require.Equal(t, true, ok)
		require.Equal(t, "key-1", kid)

		alg, ok := signer.Headers().Algorithm()
		require.Equal(t, true, ok)
		require.Equal(t, "EdDSA", alg)
	})

	t.Run("success - kid, alg not provided", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

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
