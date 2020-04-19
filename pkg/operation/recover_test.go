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
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func TestParseRecoverOperation(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
	}

	t.Run("success", func(t *testing.T) {
		request, err := getRecoverRequestBytes()
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.NoError(t, err)
		require.Equal(t, batch.OperationTypeRecover, op.Type)
	})
	t.Run("parse recover request error", func(t *testing.T) {
		schema, err := ParseRecoverOperation([]byte(""), p)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})
	t.Run("parse patch data error", func(t *testing.T) {
		recoverRequest, err := getDefaultRecoverRequest()
		require.NoError(t, err)

		recoverRequest.Delta = invalid
		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, op)
	})
	t.Run("validate patch data error", func(t *testing.T) {
		delta, err := getDelta()
		require.NoError(t, err)

		delta.Patches = []patch.Patch{}
		recoverRequest, err := getRecoverRequest(delta, getSignedDataForRecovery())
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing patches")
		require.Nil(t, op)
	})
	t.Run("parse signed data error", func(t *testing.T) {
		recoverRequest, err := getDefaultRecoverRequest()
		require.NoError(t, err)

		recoverRequest.SignedData.Payload = invalid
		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, op)
	})
	t.Run("validate signed data error", func(t *testing.T) {
		signedData := getSignedDataForRecovery()
		signedData.RecoveryKey = nil

		delta, err := getDelta()
		require.NoError(t, err)

		recoverRequest, err := getRecoverRequest(delta, signedData)
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing recovery key")
		require.Nil(t, op)
	})
}

func TestValidateSignedData(t *testing.T) {
	t.Run("missing recovery key", func(t *testing.T) {
		signed := getSignedDataForRecovery()
		signed.RecoveryKey = nil
		err := validateSignedDataForRecovery(signed, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing recovery key")
	})
	t.Run("invalid patch data hash", func(t *testing.T) {
		signed := getSignedDataForRecovery()
		signed.DeltaHash = ""
		err := validateSignedDataForRecovery(signed, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "patch data hash is not computed with the latest supported hash algorithm")
	})
	t.Run("invalid next recovery commitment hash", func(t *testing.T) {
		signed := getSignedDataForRecovery()
		signed.RecoveryCommitment = ""
		err := validateSignedDataForRecovery(signed, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery commitment hash is not computed with the latest supported hash algorithm")
	})
}

func getRecoverRequest(delta *model.DeltaModel, signedData *model.RecoverSignedDataModel) (*model.RecoverRequest, error) {
	deltaBytes, err := docutil.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	signedDataBytes, err := docutil.MarshalCanonical(signedData)
	if err != nil {
		return nil, err
	}

	return &model.RecoverRequest{
		Operation: model.OperationTypeRecover,
		DidSuffix: "suffix",
		Delta:     docutil.EncodeToString(deltaBytes),
		SignedData: &model.JWS{
			// TODO: JWS encoded
			Payload: docutil.EncodeToString(signedDataBytes),
		},
	}, nil
}

func getDefaultRecoverRequest() (*model.RecoverRequest, error) {
	delta, err := getDelta()
	if err != nil {
		return nil, err
	}
	return getRecoverRequest(delta, getSignedDataForRecovery())
}

func getSignedDataForRecovery() *model.RecoverSignedDataModel {
	return &model.RecoverSignedDataModel{
		RecoveryKey:        &jws.JWK{},
		RecoveryCommitment: computeMultihash("recoveryReveal"),
		DeltaHash:          computeMultihash("operation"),
	}
}

func getRecoverRequestBytes() ([]byte, error) {
	req, err := getDefaultRecoverRequest()
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}
