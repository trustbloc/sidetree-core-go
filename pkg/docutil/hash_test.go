/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var sample = []byte("test")

func TestGetHash(t *testing.T) {
	hash, err := GetHash(100)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "algorithm not supported")
	require.Nil(t, hash)

	hash, err = GetHash(sha2_256)
	require.Nil(t, err)
	require.NotNil(t, hash)
}

func TestComputeHash(t *testing.T) {
	hash, err := ComputeMultihash(100, sample)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "algorithm not supported")
	require.Nil(t, hash)

	hash, err = ComputeMultihash(sha2_256, sample)
	require.Nil(t, err)
	require.NotNil(t, hash)
}

func TestIsSupportedMultihash(t *testing.T) {
	// scenario: not base64 encoded (corrupted input)
	supported := IsSupportedMultihash("XXXXXaGVsbG8=")
	require.False(t, supported)

	// scenario: base64 encoded, however not multihash
	supported = IsSupportedMultihash(EncodeToString(sample))
	require.False(t, supported)

	// scenario: valid encoded multihash
	hash, err := ComputeMultihash(sha2_256, sample)
	require.Nil(t, err)
	require.NotNil(t, hash)

	key := EncodeToString(hash)
	supported = IsSupportedMultihash(key)
	require.True(t, supported)
}

func TestIsComputedUsingHashAlgorithm(t *testing.T) {
	hash, err := ComputeMultihash(sha2_256, sample)
	require.Nil(t, err)
	require.NotNil(t, hash)

	key := EncodeToString(hash)
	ok := IsComputedUsingHashAlgorithm(key, sha2_256)
	require.True(t, ok)

	// use random code to fail
	ok = IsComputedUsingHashAlgorithm(key, 55)
	require.False(t, ok)

	ok = IsComputedUsingHashAlgorithm("invalid", sha2_256)
	require.False(t, ok)
}

func TestIsValidModelMultihash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		suffix, err := CalculateModelMultihash(suffixDataObject, multihashCode)
		require.Nil(t, err)
		require.Equal(t, expectedSuffixForSuffixObject, suffix)

		err = IsValidModelMultihash(suffixDataObject, suffix)
		require.NoError(t, err)
	})

	t.Run("error - model multihash is not matching provided multihash", func(t *testing.T) {
		differentMultihash, err := ComputeMultihash(sha2_256, []byte("test"))
		require.NoError(t, err)

		err = IsValidModelMultihash(suffixDataObject, EncodeToString(differentMultihash))
		require.Error(t, err)
		require.Contains(t, err.Error(), "supplied hash doesn't match original content")
	})

	t.Run("error - multihash is not encoded", func(t *testing.T) {
		differentMultihash, err := ComputeMultihash(sha2_256, []byte("test"))
		require.NoError(t, err)

		err = IsValidModelMultihash(suffixDataObject, string(differentMultihash))
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
	})

	t.Run("error - invalid model", func(t *testing.T) {
		differentMultihash, err := ComputeMultihash(sha2_256, []byte("test"))
		require.NoError(t, err)

		var c chan int
		err = IsValidModelMultihash(c, EncodeToString(differentMultihash))
		require.Error(t, err)
		require.Contains(t, err.Error(), "json: unsupported type: chan int")
	})
}
