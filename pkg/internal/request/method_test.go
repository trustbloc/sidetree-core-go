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
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

const (
	namespace = "doc:method"
)

func TestGetParts_InitialState(t *testing.T) {
	const testDID = "doc:method:abc"

	req := model.CreateRequest{
		Delta:      &model.DeltaModel{},
		SuffixData: &model.SuffixDataModel{},
	}

	reqBytes, err := canonicalizer.MarshalCanonical(req)
	require.NoError(t, err)
	fmt.Println(string(reqBytes))

	initialState := docutil.EncodeToString(reqBytes)

	t.Run("success - just did, no initial state value", func(t *testing.T) {
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
		did, initial, err := GetParts(namespace, testDID+longFormSeparator+initialState)

		require.NoError(t, err)
		require.Equal(t, testDID, did)
		require.Equal(t, `{"delta":{},"suffix_data":{},"type":"create"}`, string(initial))
	})

	t.Run("success - did with dot in namespace and initial state", func(t *testing.T) {
		namespaceWithDot := "did:bloc:trustbloc.dev"
		didWithDot := namespaceWithDot + docutil.NamespaceDelimiter + "EiB2gB7F-aDjg8qPsTuZfVqWkJtIWXn4nObHSgtZ1IzMaQ"

		didWithDotWithInitialState := didWithDot + longFormSeparator + initialState
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
