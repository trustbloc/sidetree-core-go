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
	multihashCode  uint = 18
	didMethodName       = "did:sidetree"
	expectedSuffix      = "EiBFsUlzmZ3zJtSFeQKwJNtngjmB51ehMWWDuptf9b4Bag"
)

func TestCalculateDID(t *testing.T) {
	payload := []byte(suffixDataString)

	did, err := CalculateID(didMethodName, EncodeToString(payload), multihashCode)
	require.Nil(t, err)
	require.Equal(t, did, didMethodName+NamespaceDelimiter+expectedSuffix)
}

func TestCalculateUniqueSuffix(t *testing.T) {
	payload := []byte(suffixDataString)

	suffix, err := CalculateUniqueSuffix(EncodeToString(payload), multihashCode)
	require.Nil(t, err)
	require.Equal(t, expectedSuffix, suffix)
}

func TestDidCalculationError(t *testing.T) {
	payload := []byte("{}")

	// non-supported mulithash code will cause an error
	id, err := CalculateID(didMethodName, EncodeToString(payload), 55)
	require.NotNil(t, err)
	require.Empty(t, id)
	require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")

	// payload has to be encoded - decode error
	id, err = CalculateID(didMethodName, "!!!", sha2_256)
	require.NotNil(t, err)
	require.Empty(t, id)
	require.Contains(t, err.Error(), "illegal base64 data")
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

const suffixDataString = `{"delta_hash":"EiBXM4otLuP2fG4ZA75-anrkWVX0637xZtMJSoKop-trdw","recovery_commitment":"EiC8G4IdbD7D4Co57GjLNKhmDEabrzkO1wsKE9MQeUvOgw"}`
