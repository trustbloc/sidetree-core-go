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

func TestHandler_CreateChunkFile(t *testing.T) {
	const createOpsNum = 5
	const updateOpsNum = 4
	const deactivateOpsNum = 3
	const recoverOpsNum = 1

	ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

	chunk := CreateChunkFile(ops)
	require.NotNil(t, chunk)
	require.Equal(t, createOpsNum+updateOpsNum+recoverOpsNum, len(chunk.Deltas))
}

func TestParseChunkFile(t *testing.T) {
	const createOpsNum = 5
	const updateOpsNum = 4
	const deactivateOpsNum = 3
	const recoverOpsNum = 1

	ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

	model := CreateChunkFile(ops)
	bytes, err := json.Marshal(model)
	require.NoError(t, err)

	parsed, err := ParseChunkFile(bytes)
	require.NoError(t, err)

	require.Equal(t, createOpsNum+updateOpsNum+recoverOpsNum, len(parsed.Deltas))
}
