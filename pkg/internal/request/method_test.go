/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package request

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	namespace         = "doc:method"
	initialStateParam = "?-method-initial-state="
)

func TestGetMethodInitialParam(t *testing.T) {
	initialParam := GetInitialStateParam("did:method")
	require.Equal(t, "-method-initial-state", initialParam)

	// should never happens since namespace is configured
	initialParam = GetInitialStateParam("did")
	require.Equal(t, "--initial-state", initialParam)

	// should never happens since namespace is configured
	initialParam = GetInitialStateParam("did:")
	require.Equal(t, "--initial-state", initialParam)
}

func TestGetParts(t *testing.T) {
	const testDID = "did:method:abc"

	did, initial, err := GetParts(namespace, testDID)
	require.NoError(t, err)
	require.Equal(t, testDID, did)
	require.Empty(t, initial)

	did, initial, err = GetParts(namespace, testDID+initialStateParam)
	require.Error(t, err)
	require.Empty(t, did)
	require.Nil(t, initial)
	require.Contains(t, err.Error(), "initial values is present but empty")

	did, initial, err = GetParts(namespace, testDID+initialStateParam+"xyz")
	require.Error(t, err)
	require.Empty(t, did)
	require.Nil(t, initial)
	require.Contains(t, err.Error(), "initial state should have two parts: delta and suffix data")

	did, initial, err = GetParts(namespace, testDID+initialStateParam+"xyz.123")
	require.NoError(t, err)
	require.Equal(t, testDID, did)
	require.Equal(t, initial.Delta, "xyz")
	require.Equal(t, initial.SuffixData, "123")
	require.Equal(t, initial.Operation, model.OperationTypeCreate)
}
