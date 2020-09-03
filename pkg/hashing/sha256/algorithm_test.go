/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sha256

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlgorithm_Accept(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		alg := New()
		require.True(t, alg.Accept("SHA256"))
		require.False(t, alg.Accept("other"))
	})
}

func TestAlgorithm_Hash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		alg := New()

		test := []byte("test data")
		h := alg.Hash(test)

		expected := sha256.Sum256(test)
		require.Equal(t, expected[:], h)
	})
}

func TestAlgorithm_Close(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		alg := New()
		require.NoError(t, alg.Close())
	})
}
