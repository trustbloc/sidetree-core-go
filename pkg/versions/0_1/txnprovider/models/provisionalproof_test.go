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

func TestCreateProvisionalProofFileFile(t *testing.T) {
	const updateOpsNum = 2

	updateOps := generateOperations(updateOpsNum, operation.TypeUpdate)

	batch := CreateProvisionalProofFile(updateOps)
	require.NotNil(t, batch)
	require.Equal(t, updateOpsNum, len(batch.Operations.Update))
}

func TestParseProvisionalProofFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		const updateOpsNum = 2

		updateOps := generateOperations(updateOpsNum, operation.TypeUpdate)

		model := CreateProvisionalProofFile(updateOps)

		bytes, err := json.Marshal(model)
		require.NoError(t, err)

		parsed, err := ParseProvisionalProofFile(bytes)
		require.NoError(t, err)

		require.Equal(t, updateOpsNum, len(parsed.Operations.Update))
	})

	t.Run("error - unmarshal error", func(t *testing.T) {
		parsed, err := ParseProvisionalProofFile([]byte("not JSON"))
		require.Error(t, err)
		require.Nil(t, parsed)
		require.Contains(t, err.Error(), "failed to unmarshal provisional proof file")
	})
}
