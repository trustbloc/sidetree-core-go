/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	multihashCode uint = 18
	namespace          = "did:sidetree"
)

func TestCalculateID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		id, err := CalculateID(namespace, suffixDataObject, multihashCode)
		require.Nil(t, err)
		require.Equal(t, namespace+NamespaceDelimiter+expectedSuffixForSuffixObject, id)
	})

	t.Run("error - multihash algorithm not supported", func(t *testing.T) {
		id, err := CalculateID(namespace, suffixDataObject, 55)
		require.NotNil(t, err)
		require.Empty(t, id)
		require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")
	})
}

func TestCalculateModelMultihash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		suffix, err := CalculateModelMultihash(suffixDataObject, multihashCode)
		require.Nil(t, err)
		require.Equal(t, expectedSuffixForSuffixObject, suffix)
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

func TestDidCalculationError(t *testing.T) {
	// non-supported mulithash code will cause an error
	id, err := CalculateID(namespace, suffixDataObject, 55)
	require.NotNil(t, err)
	require.Empty(t, id)
	require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")

	// payload has to be JSON object in order to canonicalize
	id, err = CalculateID(namespace, "!!!", sha2_256)
	require.NotNil(t, err)
	require.Empty(t, id)
	require.Contains(t, err.Error(), "Expected '{'")
}

func TestNamespaceFromID(t *testing.T) {
	const namespace = "did:sidetree"
	const suffix = "123456"

	t.Run("Valid ID", func(t *testing.T) {
		ns, err := GetNamespaceFromID(namespace + NamespaceDelimiter + suffix)
		require.NoError(t, err)
		require.Equal(t, namespace, ns)
	})

	t.Run("Invalid ID", func(t *testing.T) {
		ns, err := GetNamespaceFromID(suffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid ID")
		require.Empty(t, ns)
	})
}

var suffixDataObject = &struct {
	DeltaHash          string `json:"delta_hash,omitempty"`
	RecoveryCommitment string `json:"recovery_commitment,omitempty"`
}{
	DeltaHash:          "EiDv_M8oOqyYyWtvqAGG8CpXJlKXP4Q5D4H0zE55-PQqGw",
	RecoveryCommitment: "EiAL35tvU7ge-hZm2cBRG5IrY2St2NSXUar-H8RYBMKSCg",
}

const expectedSuffixForSuffixObject = "EiDMM0OSF_J1SyCRFj-NtsyuXLP1HoFl-77QejaEwMW-kA"
