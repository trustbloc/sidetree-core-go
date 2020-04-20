/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	require.Empty(t, pk.ID())
	require.Empty(t, pk.Type())
	require.Empty(t, pk.Controller())

	pk = NewPublicKey(map[string]interface{}{
		"id":         "did:example:123456789abcdefghi#keys-1",
		"type":       "JwsVerificationKey2020",
		"controller": "did:example:123456789abcdefghi",
	})
	require.Equal(t, "did:example:123456789abcdefghi#keys-1", pk.ID())
	require.Equal(t, "JwsVerificationKey2020", pk.Type())
	require.Equal(t, "did:example:123456789abcdefghi", pk.Controller())
	require.Empty(t, pk.Usage())
	require.Empty(t, pk.JWK())
	require.Empty(t, pk.PublicKeyJwk())
	require.Empty(t, pk.PublicKeyBase58())

	require.NotEmpty(t, pk.JSONLdObject())
}

func TestInternalPublicKeyJWK(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{
		"jwk": map[string]interface{}{
			"kty": "kty",
			"crv": "crv",
			"x":   "x",
			"y":   "y",
		},
	})

	jwk := pk.JWK()
	require.Equal(t, "kty", jwk.Kty())
	require.Equal(t, "crv", jwk.Crv())
	require.Equal(t, "x", jwk.X())
	require.Equal(t, "y", jwk.Y())

	pk = NewPublicKey(map[string]interface{}{
		"jwk": "invalid",
	})

	jwk = pk.JWK()
	require.Nil(t, jwk)
}

func TestPublicKeyJWK(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{
		"publicKeyJwk": map[string]interface{}{
			"kty": "kty",
			"crv": "crv",
			"x":   "x",
			"y":   "y",
		},
	})

	jwk := pk.PublicKeyJwk()
	require.Equal(t, "kty", jwk.Kty())
	require.Equal(t, "crv", jwk.Crv())
	require.Equal(t, "x", jwk.X())
	require.Equal(t, "y", jwk.Y())

	pk = NewPublicKey(map[string]interface{}{
		"publicKeyJwk": "invalid",
	})

	jwk = pk.PublicKeyJwk()
	require.Nil(t, jwk)
}
