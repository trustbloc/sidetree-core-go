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

	initialParam = GetInitialStateParam("did:mymethod:network")
	require.Equal(t, "-mymethod-initial-state", initialParam)

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
	require.Contains(t, err.Error(), "initial state is present but empty")

	did, initial, err = GetParts(namespace, testDID+initialStateParam+"xyz")
	require.Error(t, err)
	require.Empty(t, did)
	require.Nil(t, initial)
	require.Contains(t, err.Error(), "initial state should have two parts: suffix data and delta")

	did, initial, err = GetParts(namespace, testDID+initialStateParam+"xyz.123")
	require.NoError(t, err)
	require.Equal(t, testDID, did)
	require.Equal(t, initial.Delta, "123")
	require.Equal(t, initial.SuffixData, "xyz")
	require.Equal(t, initial.Operation, model.OperationTypeCreate)

	did, initial, err = GetParts(namespace, testDID+":xyz.123")
	require.NoError(t, err)
	require.Equal(t, testDID, did)
	require.Equal(t, initial.Delta, "123")
	require.Equal(t, initial.SuffixData, "xyz")
	require.Equal(t, initial.Operation, model.OperationTypeCreate)
}

func TestGetInitialState(t *testing.T) {
	req := &model.CreateRequest{
		Operation:  "create",
		SuffixData: "abc",
		Delta:      "xyz",
	}

	resultInitialState := GetInitialState(req)
	require.Equal(t, "abc"+initialStateSeparator+"xyz", resultInitialState)
}
