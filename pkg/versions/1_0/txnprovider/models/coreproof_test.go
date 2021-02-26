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

func TestCreateCoreProofFile(t *testing.T) {
	const deactivateOpsNum = 2
	const recoverOpsNum = 2

	recoverOps := generateOperations(recoverOpsNum, operation.TypeRecover)
	deactivateOps := generateOperations(deactivateOpsNum, operation.TypeDeactivate)

	af := CreateCoreProofFile(recoverOps, deactivateOps)
	require.NotNil(t, af)
	require.Equal(t, deactivateOpsNum, len(af.Operations.Deactivate))
	require.Equal(t, recoverOpsNum, len(af.Operations.Recover))
}

func TestParseCoreProofFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		const deactivateOpsNum = 3
		const recoverOpsNum = 1

		recoverOps := generateOperations(recoverOpsNum, operation.TypeRecover)
		deactivateOps := generateOperations(deactivateOpsNum, operation.TypeDeactivate)

		model := CreateCoreProofFile(recoverOps, deactivateOps)

		bytes, err := json.Marshal(model)
		require.NoError(t, err)

		parsed, err := ParseCoreProofFile(bytes)
		require.NoError(t, err)

		require.Equal(t, deactivateOpsNum, len(parsed.Operations.Deactivate))
		require.Equal(t, recoverOpsNum, len(parsed.Operations.Recover))
	})

	t.Run("error - unmarshal error", func(t *testing.T) {
		parsed, err := ParseCoreProofFile([]byte("not JSON"))
		require.Error(t, err)
		require.Nil(t, parsed)
		require.Contains(t, err.Error(), "failed to unmarshal core proof file")
	})
}
