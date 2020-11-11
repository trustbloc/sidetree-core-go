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
	sha2_256  uint = 18
	namespace      = "did:sidetree"
)

func TestCalculateID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		id, err := CalculateID(namespace, suffixDataObject, sha2_256)
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
	DeltaHash          string `json:"deltaHash,omitempty"`
	RecoveryCommitment string `json:"recoveryCommitment,omitempty"`
}{
	DeltaHash:          "EiBOmkP6kn7yjt0VocmcPu9OQOsZi199Evh-xB48ebubQA",
	RecoveryCommitment: "EiAAZJYry29vICkwmso8FL92WAISMAhsL8xkCm8dYVnq_w",
}

const expectedSuffixForSuffixObject = "EiA5vyaRzJIxbkuZbvwEXiC__u8ieFx50TAAo98tBzCuyA"
