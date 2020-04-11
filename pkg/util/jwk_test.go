/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetECPublicKey(t *testing.T) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		jwk, err := GetECPublicKey(privateKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwk)
		require.Equal(t, "P-256", jwk.Crv)
		require.Equal(t, "EC", jwk.Kty)
	})

	t.Run("marshall error", func(t *testing.T) {
		privateKey.PublicKey = ecdsa.PublicKey{
			Curve: nil,
			X:     nil,
			Y:     nil,
		}

		jwk, err := GetECPublicKey(privateKey)
		require.Error(t, err)
		require.Nil(t, jwk)
		require.Contains(t, err.Error(), "invalid EC key")
	})
}
