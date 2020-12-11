/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hashing

import (
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
)

const (
	algSHA256 = 5

	sha2_256 = 18
	sha2_512 = 19
)

var sample = []byte("test")

func TestGetHashFromMultihash(t *testing.T) {
	hash, err := GetHashFromMultihash(100)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "algorithm not supported")
	require.Equal(t, crypto.Hash(0), hash)

	hash, err = GetHashFromMultihash(sha2_256)
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
	supported = IsSupportedMultihash(encoder.EncodeToString(sample))
	require.False(t, supported)

	// scenario: valid encoded multihash
	hash, err := ComputeMultihash(sha2_256, sample)
	require.Nil(t, err)
	require.NotNil(t, hash)

	key := encoder.EncodeToString(hash)
	supported = IsSupportedMultihash(key)
	require.True(t, supported)
}

func TestIsComputedUsingHashAlgorithm(t *testing.T) {
	hash, err := ComputeMultihash(sha2_256, sample)
	require.Nil(t, err)
	require.NotNil(t, hash)

	key := encoder.EncodeToString(hash)
	ok := IsComputedUsingMultihashAlgorithms(key, []uint{sha2_256})
	require.True(t, ok)

	// use random code to fail
	ok = IsComputedUsingMultihashAlgorithms(key, []uint{55})
	require.False(t, ok)

	ok = IsComputedUsingMultihashAlgorithms("invalid", []uint{sha2_256})
	require.False(t, ok)
}

func TestIsValidModelMultihash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		suffix, err := CalculateModelMultihash(suffixDataObject, sha2_256)
		require.Nil(t, err)
		require.Equal(t, expectedSuffixForSuffixObject, suffix)

		err = IsValidModelMultihash(suffixDataObject, suffix)
		require.NoError(t, err)
	})

	t.Run("error - model multihash is not matching provided multihash", func(t *testing.T) {
		differentMultihash, err := ComputeMultihash(sha2_256, []byte("test"))
		require.NoError(t, err)

		err = IsValidModelMultihash(suffixDataObject, encoder.EncodeToString(differentMultihash))
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
		err = IsValidModelMultihash(c, encoder.EncodeToString(differentMultihash))
		require.Error(t, err)
		require.Contains(t, err.Error(), "json: unsupported type: chan int")
	})
}

func TestCalculateModelMultihash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		suffix, err := CalculateModelMultihash(suffixDataObject, sha2_256)
		require.Nil(t, err)
		require.Equal(t, expectedSuffixForSuffixObject, suffix)
	})

	t.Run("success", func(t *testing.T) {
		_, err := CalculateModelMultihash(suffixDataObject, sha2_512)
		require.Nil(t, err)
	})

	t.Run("error - multihash algorithm not supported", func(t *testing.T) {
		id, err := CalculateModelMultihash(suffixDataObject, 55)
		require.NotNil(t, err)
		require.Empty(t, id)
		require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")
	})

	t.Run("error - marshal canonical", func(t *testing.T) {
		var c chan int
		result, err := CalculateModelMultihash(c, sha2_256)
		require.Error(t, err)
		require.Empty(t, result)
		require.Contains(t, err.Error(), "json: unsupported type: chan int")
	})
}

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

var suffixDataObject = &struct {
	DeltaHash          string `json:"deltaHash,omitempty"`
	RecoveryCommitment string `json:"recoveryCommitment,omitempty"`
}{
	DeltaHash:          "EiBOmkP6kn7yjt0VocmcPu9OQOsZi199Evh-xB48ebubQA",
	RecoveryCommitment: "EiAAZJYry29vICkwmso8FL92WAISMAhsL8xkCm8dYVnq_w",
}

const expectedSuffixForSuffixObject = "EiA5vyaRzJIxbkuZbvwEXiC__u8ieFx50TAAo98tBzCuyA"
