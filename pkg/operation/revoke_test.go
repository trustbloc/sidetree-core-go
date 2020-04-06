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
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
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
	t.Run("parse request", func(t *testing.T) {
		request, err := json.Marshal("invalidJSON")
		require.NoError(t, err)

		op, err := ParseRevokeOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot unmarshal string")
		require.Nil(t, op)
	})
	t.Run("parse signed data error - decoding failed", func(t *testing.T) {
		revokeRequest, err := getDefaultRevokeRequest()
		require.NoError(t, err)

		revokeRequest.SignedData.Payload = invalid
		request, err := json.Marshal(revokeRequest)
		require.NoError(t, err)

		op, err := ParseRevokeOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
		require.Nil(t, op)
	})
	t.Run("parse signed data error - invalid JSON", func(t *testing.T) {
		revokeRequest, err := getDefaultRevokeRequest()
		require.NoError(t, err)

		revokeRequest.SignedData.Payload = docutil.EncodeToString([]byte("invalidJSON"))
		request, err := json.Marshal(revokeRequest)
		require.NoError(t, err)

		op, err := ParseRevokeOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, op)
	})
	t.Run("validate signed data error - did suffix mismatch", func(t *testing.T) {
		signedData := getSignedDataForRevoke()
		signedData.DidUniqueSuffix = "different"

		recoverRequest, err := getRevokeRequest(signedData)
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRevokeOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signed did suffix mismatch for revoke")
		require.Nil(t, op)
	})
	t.Run("validate signed data error - reveal value mismatch", func(t *testing.T) {
		signedData := getSignedDataForRevoke()
		signedData.RecoveryRevealValue = "different"

		recoverRequest, err := getRevokeRequest(signedData)
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRevokeOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signed recovery reveal mismatch for revoke")
		require.Nil(t, op)
	})
}

func getRevokeRequest(signedData *model.RevokeSignedDataModel) (*model.RevokeRequest, error) {
	signedDataBytes, err := docutil.MarshalCanonical(signedData)
	if err != nil {
		return nil, err
	}

	jws := &model.JWS{
		Payload: docutil.EncodeToString(signedDataBytes),
	}

	return &model.RevokeRequest{
		Operation:           model.OperationTypeRevoke,
		DidUniqueSuffix:     "did",
		RecoveryRevealValue: "recoveryReveal",
		SignedData:          jws,
	}, nil
}

func getDefaultRevokeRequest() (*model.RevokeRequest, error) {
	return getRevokeRequest(getSignedDataForRevoke())
}

func getSignedDataForRevoke() *model.RevokeSignedDataModel {
	return &model.RevokeSignedDataModel{
		DidUniqueSuffix:     "did",
		RecoveryRevealValue: "recoveryReveal",
	}
}

func getRevokeRequestBytes() ([]byte, error) {
	req, err := getRevokeRequest(getSignedDataForRevoke())
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}
