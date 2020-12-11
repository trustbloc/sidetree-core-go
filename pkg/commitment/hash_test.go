/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commitment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

const (
	sha2_256 uint = 18 // multihash code
)

func TestGetCommitment(t *testing.T) {
	jwk := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
		Y:   "y",
	}

	t.Run("success", func(t *testing.T) {
		commitment, err := GetCommitment(jwk, sha2_256)
		require.NoError(t, err)
		require.NotEmpty(t, commitment)
	})

	t.Run(" error - multihash not supported", func(t *testing.T) {
		commitment, err := GetCommitment(jwk, 55)
		require.Error(t, err)
		require.Empty(t, commitment)
		require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")
	})

	t.Run("error - canonicalization failed", func(t *testing.T) {
		commitment, err := GetCommitment(nil, sha2_256)
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

func TestGetRevealValue(t *testing.T) {
	jwk := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
		Y:   "y",
	}

	t.Run("success", func(t *testing.T) {
		rv, err := GetRevealValue(jwk, sha2_256)
		require.NoError(t, err)
		require.NotEmpty(t, rv)
	})

	t.Run("error - wrong multihash code", func(t *testing.T) {
		rv, err := GetRevealValue(jwk, 55)
		require.Error(t, err)
		require.Empty(t, rv)
		require.Contains(t, err.Error(), "failed to get reveal value: algorithm not supported, unable to compute hash")
	})
}

func TestGetCommitmentFromRevealValue(t *testing.T) {
	jwk := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
		Y:   "y",
	}

	t.Run("success", func(t *testing.T) {
		rv, err := GetRevealValue(jwk, sha2_256)
		require.NoError(t, err)

		cFromRv, err := GetCommitmentFromRevealValue(rv)
		require.NoError(t, err)

		c, err := GetCommitment(jwk, sha2_256)
		require.NoError(t, err)
		require.Equal(t, c, cFromRv)
	})

	t.Run("error - reveal value is not a multihash", func(t *testing.T) {
		cFromRv, err := GetCommitmentFromRevealValue("reveal")
		require.Error(t, err)
		require.Empty(t, cFromRv)
		require.Contains(t, err.Error(), "failed to get commitment from reveal value")
	})
}
