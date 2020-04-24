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

func TestParseDeactivateOperation(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
	}

	t.Run("success", func(t *testing.T) {
		payload, err := getDeactivateRequestBytes()
		require.NoError(t, err)

		op, err := ParseDeactivateOperation(payload, p)
		require.NoError(t, err)
		require.Equal(t, batch.OperationTypeDeactivate, op.Type)
	})
	t.Run("missing unique suffix", func(t *testing.T) {
		schema, err := ParseDeactivateOperation([]byte("{}"), p)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "missing unique suffix")
	})
	t.Run("missing signed data", func(t *testing.T) {
		op, err := ParseDeactivateOperation([]byte(`{"did_suffix":"abc"}`), p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signed data")
		require.Nil(t, op)
	})
	t.Run("parse request", func(t *testing.T) {
		request, err := json.Marshal("invalidJSON")
		require.NoError(t, err)

		op, err := ParseDeactivateOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot unmarshal string")
		require.Nil(t, op)
	})
	t.Run("parse signed data error - decoding failed", func(t *testing.T) {
		deactivateRequest, err := getDefaultDeactivateRequest()
		require.NoError(t, err)

		deactivateRequest.SignedData.Payload = invalid
		request, err := json.Marshal(deactivateRequest)
		require.NoError(t, err)

		op, err := ParseDeactivateOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, op)
	})
	t.Run("parse signed data error - invalid JSON", func(t *testing.T) {
		deactivateRequest, err := getDefaultDeactivateRequest()
		require.NoError(t, err)

		deactivateRequest.SignedData.Payload = docutil.EncodeToString([]byte("invalidJSON"))
		request, err := json.Marshal(deactivateRequest)
		require.NoError(t, err)

		op, err := ParseDeactivateOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, op)
	})
	t.Run("validate signed data error - did suffix mismatch", func(t *testing.T) {
		signedData := getSignedDataForDeactivate()
		signedData.DidSuffix = "different"

		recoverRequest, err := getDeactivateRequest(signedData)
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseDeactivateOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signed did suffix mismatch for deactivate")
		require.Nil(t, op)
	})
	t.Run("validate signed data error - reveal value mismatch", func(t *testing.T) {
		signedData := getSignedDataForDeactivate()
		signedData.RecoveryRevealValue = "different"

		recoverRequest, err := getDeactivateRequest(signedData)
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseDeactivateOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signed recovery reveal mismatch for deactivate")
		require.Nil(t, op)
	})
}

func getDeactivateRequest(signedData *model.DeactivateSignedDataModel) (*model.DeactivateRequest, error) {
	signedDataBytes, err := docutil.MarshalCanonical(signedData)
	if err != nil {
		return nil, err
	}

	jws := &model.JWS{
		Protected: &model.Header{
			Alg: "alg",
			Kid: "kid",
		},
		Payload:   docutil.EncodeToString(signedDataBytes),
		Signature: "signature",
	}

	return &model.DeactivateRequest{
		Operation:           model.OperationTypeDeactivate,
		DidSuffix:           "did",
		RecoveryRevealValue: "recoveryReveal",
		SignedData:          jws,
	}, nil
}

func getDefaultDeactivateRequest() (*model.DeactivateRequest, error) {
	return getDeactivateRequest(getSignedDataForDeactivate())
}

func getSignedDataForDeactivate() *model.DeactivateSignedDataModel {
	return &model.DeactivateSignedDataModel{
		DidSuffix:           "did",
		RecoveryRevealValue: "recoveryReveal",
	}
}

func getDeactivateRequestBytes() ([]byte, error) {
	req, err := getDeactivateRequest(getSignedDataForDeactivate())
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}
