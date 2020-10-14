/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJWK(t *testing.T) {
	jwk := NewJWK(map[string]interface{}{})
	require.Empty(t, jwk.Kty())
	require.Empty(t, jwk.Crv())
	require.Empty(t, jwk.Y())
	require.Empty(t, jwk.Y())

	jwk = NewJWK(map[string]interface{}{
		"kty": "kty",
		"crv": "crv",
		"x":   "x",
		"y":   "y",
	})

	require.Equal(t, "kty", jwk.Kty())
	require.Equal(t, "crv", jwk.Crv())
	require.Equal(t, "x", jwk.X())
	require.Equal(t, "y", jwk.Y())
}

func TestValidate(t *testing.T) {
	t.Run("missing kty", func(t *testing.T) {
		jwk := JWK{
			"kty": "",
			"crv": "crv",
			"x":   "x",
			"y":   "y",
		}

		err := jwk.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWK kty is missing")
	})

	t.Run("missing crv", func(t *testing.T) {
		jwk := JWK{
			"kty": "kty",
			"crv": "",
			"x":   "x",
			"y":   "y",
		}

		err := jwk.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWK crv is missing")
	})

	t.Run("missing x", func(t *testing.T) {
		jwk := JWK{
			"kty": "kty",
			"crv": "crv",
			"x":   "",
			"y":   "y",
		}

		err := jwk.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWK x is missing")
	})
}
