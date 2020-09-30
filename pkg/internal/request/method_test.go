/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package request

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
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

func TestGetParts_IntialStateParam(t *testing.T) {
	const testDID = "doc:method:abc"

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
	require.Equal(t, `{"delta":"123","suffix_data":"xyz","type":"create"}`, string(initial))
}

func TestGetParts_InitialStateJCS(t *testing.T) {
	const testDID = "doc:method:abc"

	req := model.CreateRequestJCS{
		Delta:      &model.DeltaModel{},
		SuffixData: &model.SuffixDataModel{},
	}

	reqBytes, err := canonicalizer.MarshalCanonical(req)
	require.NoError(t, err)
	fmt.Println(string(reqBytes))

	initialStateJCS := docutil.EncodeToString(reqBytes)

	t.Run("success - just did, no initial state parameter", func(t *testing.T) {
		did, initial, err := GetParts(namespace, testDID)
		require.NoError(t, err)
		require.Equal(t, testDID, did)
		require.Empty(t, initial)
	})

	t.Run("success - did with dot in namespace", func(t *testing.T) {
		namespaceWithDot := "did:bloc:trustbloc.dev"
		didWithDot := namespaceWithDot + docutil.NamespaceDelimiter + "EiB2gB7F-aDjg8qPsTuZfVqWkJtIWXn4nObHSgtZ1IzMaQ"

		did, initial, err := GetParts(namespaceWithDot, didWithDot)
		require.NoError(t, err)
		require.Equal(t, didWithDot, did)
		require.Nil(t, initial)
	})

	t.Run("success - did with initial state JCS", func(t *testing.T) {
		did, initial, err := GetParts(namespace, testDID+longFormSeparator+initialStateJCS)

		require.NoError(t, err)
		require.Equal(t, testDID, did)
		require.Equal(t, `{"delta":{},"suffix_data":{},"type":"create"}`, string(initial))
	})

	t.Run("success - did with dot in namespace and initial state", func(t *testing.T) {
		namespaceWithDot := "did:bloc:trustbloc.dev"
		didWithDot := namespaceWithDot + docutil.NamespaceDelimiter + "EiB2gB7F-aDjg8qPsTuZfVqWkJtIWXn4nObHSgtZ1IzMaQ"

		didWithDotWithInitialState := didWithDot + longFormSeparator + initialStateJCS
		did, initial, err := GetParts(namespaceWithDot, didWithDotWithInitialState)
		require.NoError(t, err)
		require.Equal(t, didWithDot, did)
		require.Equal(t, `{"delta":{},"suffix_data":{},"type":"create"}`, string(initial))
	})

	t.Run("error - initial state not encoded", func(t *testing.T) {
		notEncoded := "not encoded"

		did, initial, err := GetParts(namespace, testDID+longFormSeparator+notEncoded)
		require.Error(t, err)
		require.Empty(t, did)
		require.Nil(t, initial)
		require.Contains(t, err.Error(), "illegal base64 data")
	})

	t.Run("error - initial state not JSON", func(t *testing.T) {
		invalidJCS := docutil.EncodeToString([]byte(`not JSON`))

		did, initial, err := GetParts(namespace, testDID+longFormSeparator+invalidJCS)
		require.Error(t, err)
		require.Empty(t, did)
		require.Nil(t, initial)
		require.Contains(t, err.Error(), "invalid character")
	})

	t.Run("error - initial state not expected JCS", func(t *testing.T) {
		unexpectedJCS := docutil.EncodeToString([]byte(`{"key":"value"}`))

		did, initial, err := GetParts(namespace, testDID+longFormSeparator+unexpectedJCS)
		require.Error(t, err)
		require.Empty(t, did)
		require.Nil(t, initial)
		require.Contains(t, err.Error(), "initial state JCS is not valid")
	})
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
