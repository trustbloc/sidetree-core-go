/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func TestParseRevokeOperation(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewUpdateHandler(docHandler)

	t.Run("success", func(t *testing.T) {
		payload, err := getRevokeRequestBytes()
		require.NoError(t, err)

		op, err := handler.parseRevokeOperation(payload)
		require.NoError(t, err)
		require.Equal(t, batch.OperationTypeRevoke, op.Type)
	})
	t.Run("missing unique suffix", func(t *testing.T) {
		schema, err := handler.parseRevokeOperation([]byte("{}"))
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "missing unique suffix")
	})
}

func getRevokeRequest() *model.RevokeRequest {
	return &model.RevokeRequest{
		Operation:           model.OperationTypeRevoke,
		DidUniqueSuffix:     "did",
		RecoveryOTP:         "recoveryOTP",
		SignedOperationData: nil,
	}
}

func getRevokeRequestBytes() ([]byte, error) {
	return json.Marshal(getRevokeRequest())
}
