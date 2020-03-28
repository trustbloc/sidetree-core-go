/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const sha2_256 = 18

func TestParseRevokeOperation(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
	}

	t.Run("success", func(t *testing.T) {
		payload, err := getRevokeRequestBytes()
		require.NoError(t, err)

		op, err := ParseRevokeOperation(payload, p)
		require.NoError(t, err)
		require.Equal(t, batch.OperationTypeRevoke, op.Type)
	})
	t.Run("missing unique suffix", func(t *testing.T) {
		schema, err := ParseRevokeOperation([]byte("{}"), p)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "missing unique suffix")
	})
}

func getRevokeRequest() *model.RevokeRequest {
	return &model.RevokeRequest{
		Operation:       model.OperationTypeRevoke,
		DidUniqueSuffix: "did",
		RecoveryOTP:     "recoveryOTP",
		SignedData:      nil,
	}
}

func getRevokeRequestBytes() ([]byte, error) {
	return json.Marshal(getRevokeRequest())
}
