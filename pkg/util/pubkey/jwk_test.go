/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
)

func TestGetPublicKeyJWK(t *testing.T) {
	t.Run("success EC P-256", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := GetPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwk)
		require.Equal(t, "P-256", jwk.Crv)
		require.Equal(t, "EC", jwk.Kty)
	})

	t.Run("success EC secp256k1 ", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := GetPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwk)
		require.Equal(t, "secp256k1", jwk.Crv)
		require.Equal(t, "EC", jwk.Kty)
	})

	t.Run("success ED25519", func(t *testing.T) {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := GetPublicKeyJWK(publicKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwk)
		require.Equal(t, "Ed25519", jwk.Crv)
		require.Equal(t, "OKP", jwk.Kty)
	})

	t.Run("unknown key type", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := GetPublicKeyJWK(privateKey)
		require.Error(t, err)
		require.Nil(t, jwk)
		require.Contains(t, err.Error(), "unknown key type")
	})
	t.Run("marshall error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		privateKey.PublicKey = ecdsa.PublicKey{
			Curve: nil,
			X:     nil,
			Y:     nil,
		}

		jwk, err := GetPublicKeyJWK(&privateKey.PublicKey)
		require.Error(t, err)
		require.Nil(t, jwk)
		require.Contains(t, err.Error(), "invalid EC key")
	})
}
