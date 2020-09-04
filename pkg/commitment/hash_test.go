/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commitment

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

const (
	sha2_256 uint = 18 // multihash code
)

func TestCalculate(t *testing.T) {
	jwk := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
		Y:   "y",
	}

	t.Run("success", func(t *testing.T) {
		commitment, err := Calculate(jwk, sha2_256, crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, commitment)
	})

	t.Run(" error - multihash not supported", func(t *testing.T) {
		commitment, err := Calculate(jwk, 55, crypto.SHA256)
		require.Error(t, err)
		require.Empty(t, commitment)
		require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")
	})

	t.Run(" error - hash not supported", func(t *testing.T) {
		commitment, err := Calculate(jwk, sha2_256, 55)
		require.Error(t, err)
		require.Empty(t, commitment)
		require.Contains(t, err.Error(), "hash function not available for: 55")
	})

	t.Run("error - canonicalization failed", func(t *testing.T) {
		commitment, err := Calculate(nil, sha2_256, crypto.SHA256)
		require.Error(t, err)
		require.Empty(t, commitment)
		require.Contains(t, err.Error(), "Expected '{' but got 'n'")
	})

	t.Run("interop test", func(t *testing.T) {
		jwk := &jws.JWK{
			Kty: "EC",
			Crv: "secp256k1",
			X:   "5s3-bKjD1Eu_3NJu8pk7qIdOPl1GBzU_V8aR3xiacoM",
			Y:   "v0-Q5H3vcfAfQ4zsebJQvMrIg3pcsaJzRvuIYZ3_UOY",
		}

		canonicalized, err := canonicalizer.MarshalCanonical(jwk)
		require.NoError(t, err)

		expected := `{"crv":"secp256k1","kty":"EC","x":"5s3-bKjD1Eu_3NJu8pk7qIdOPl1GBzU_V8aR3xiacoM","y":"v0-Q5H3vcfAfQ4zsebJQvMrIg3pcsaJzRvuIYZ3_UOY"}`
		require.Equal(t, string(canonicalized), expected)
	})
}
