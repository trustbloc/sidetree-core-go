/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hashing

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

const algSHA256 = 5

func TestHash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		test := []byte("hello world")

		h, err := GetHash(algSHA256, test)
		require.NoError(t, err)
		require.NotEmpty(t, h)

		expected := sha256.Sum256(test)
		require.Equal(t, expected[:], h)
	})

	t.Run("error - hash code not supported", func(t *testing.T) {
		test := []byte("test data")
		h, err := GetHash(55, test)
		require.Error(t, err)
		require.Empty(t, h)
		require.Contains(t, err.Error(), "hash function not available for: 55")
	})
}
