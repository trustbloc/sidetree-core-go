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
