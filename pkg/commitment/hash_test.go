/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commitment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

const (
	sha2_256 uint = 18
)

func TestCalculate(t *testing.T) {
	jwk := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
		Y:   "y",
	}

	t.Run("success", func(t *testing.T) {
		commitment, err := Calculate(jwk, sha2_256)
		require.NoError(t, err)
		require.NotEmpty(t, commitment)
	})

	t.Run(" error - multihash not supported", func(t *testing.T) {
		commitment, err := Calculate(jwk, 55)
		require.Error(t, err)
		require.Empty(t, commitment)
		require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")
	})

	t.Run("error - canonicalization failed", func(t *testing.T) {
		commitment, err := Calculate(nil, sha2_256)
		require.Error(t, err)
		require.Empty(t, commitment)
		require.Contains(t, err.Error(), "Expected '{' but got 'n'")
	})
}
