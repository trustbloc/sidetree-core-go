/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
)

func TestHandler_CreateMapFile(t *testing.T) {
	const updateOpsNum = 2

	ops := generateOperations(updateOpsNum, operation.TypeUpdate)

	chunks := []string{"chunk_uri"}
	batch := CreateProvisionalIndexFile(chunks, "provisionalURI", ops)
	require.NotNil(t, batch)
	require.Equal(t, updateOpsNum, len(batch.Operations.Update))
}

func TestHandler_ParseMapFile(t *testing.T) {
	const updateOpsNum = 5

	ops := generateOperations(updateOpsNum, operation.TypeUpdate)

	chunks := []string{"chunk_uri"}
	model := CreateProvisionalIndexFile(chunks, "provisionalURI", ops)

	bytes, err := json.Marshal(model)
	require.NoError(t, err)

	parsed, err := ParseProvisionalIndexFile(bytes)
	require.NoError(t, err)

	require.Equal(t, updateOpsNum, len(parsed.Operations.Update))

	require.Equal(t, parsed.Operations.Update[0].RevealValue, revealValue)
}

func TestMarshalProvisionalIndexFile(t *testing.T) {
	t.Run("success - provisional index with no operations ", func(t *testing.T) {
		model := CreateProvisionalIndexFile([]string{"chunkURI"}, "", nil)
		bytes, err := canonicalizer.MarshalCanonical(model)
		require.NoError(t, err)
		require.Equal(t, `{"chunks":[{"chunkFileUri":"chunkURI"}]}`, string(bytes))
	})
	t.Run("success - provisional index with operations", func(t *testing.T) {
		model := CreateProvisionalIndexFile([]string{"chunkURI"}, "", generateOperations(1, operation.TypeUpdate))
		bytes, err := canonicalizer.MarshalCanonical(model)
		require.NoError(t, err)
		require.Equal(t, `{"chunks":[{"chunkFileUri":"chunkURI"}],"operations":{"update":[{"didSuffix":"update-1","revealValue":"reveal-value"}]}}`, string(bytes))
	})
}
