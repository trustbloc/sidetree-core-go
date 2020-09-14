/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandler_CreateMapFile(t *testing.T) {
	const createOpsNum = 2
	const updateOpsNum = 2
	const deactivateOpsNum = 2
	const recoverOpsNum = 2

	ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

	chunks := []string{"chunk_uri"}
	batch := CreateMapFile(chunks, ops)
	require.NotNil(t, batch)
	require.Equal(t, updateOpsNum, len(batch.Operations.Update))
	require.Equal(t, 0, len(batch.Operations.Create))
	require.Equal(t, 0, len(batch.Operations.Deactivate))
	require.Equal(t, 0, len(batch.Operations.Recover))
}

func TestHandler_ParseMapFile(t *testing.T) {
	const createOpsNum = 2
	const updateOpsNum = 2
	const deactivateOpsNum = 2
	const recoverOpsNum = 2

	ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

	chunks := []string{"chunk_uri"}
	model := CreateMapFile(chunks, ops)

	bytes, err := json.Marshal(model)
	require.NoError(t, err)

	parsed, err := ParseMapFile(bytes)
	require.NoError(t, err)

	require.Equal(t, 0, len(parsed.Operations.Create))
	require.Equal(t, updateOpsNum, len(parsed.Operations.Update))
	require.Equal(t, 0, len(parsed.Operations.Deactivate))
	require.Equal(t, 0, len(parsed.Operations.Recover))
}
