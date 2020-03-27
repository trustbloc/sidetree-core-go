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
	t.Run("parse operation data error", func(t *testing.T) {
		recoverRequest, err := getDefaultRecoverRequest()
		require.NoError(t, err)

		recoverRequest.OperationData = invalid
		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
		require.Nil(t, op)
	})
	t.Run("validate operation data error", func(t *testing.T) {
		opData := getOperationData()
		opData.Patches = []patch.Patch{}
		recoverRequest, err := getRecoverRequest(opData, getSignedOperationData())
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing operation patch")
		require.Nil(t, op)
	})
	t.Run("parse signed operation data error", func(t *testing.T) {
		recoverRequest, err := getDefaultRecoverRequest()
		require.NoError(t, err)

		recoverRequest.SignedOperationData.Payload = invalid
		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
		require.Nil(t, op)
	})
	t.Run("validate signed operation data error", func(t *testing.T) {
		signedOpData := getSignedOperationData()
		signedOpData.RecoveryKey.PublicKeyHex = ""
		recoverRequest, err := getRecoverRequest(getOperationData(), signedOpData)
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing recovery key")
		require.Nil(t, op)
	})
}

func TestValidateSignedOperationData(t *testing.T) {
	t.Run("missing recovery key", func(t *testing.T) {
		signed := getSignedOperationData()
		signed.RecoveryKey.PublicKeyHex = ""
		err := validateSignedOperationData(signed, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing recovery key")
	})
	t.Run("invalid operation data hash", func(t *testing.T) {
		signed := getSignedOperationData()
		signed.OperationDataHash = ""
		err := validateSignedOperationData(signed, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "operation data hash is not computed with the latest supported hash algorithm")
	})
	t.Run("invalid next recovery OTP hash", func(t *testing.T) {
		signed := getSignedOperationData()
		signed.NextRecoveryOTPHash = ""
		err := validateSignedOperationData(signed, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery OTP hash is not computed with the latest supported hash algorithm")
	})
}

func getRecoverRequest(opData *model.OperationDataModel, signedOpData *model.SignedOperationDataSchema) (*model.RecoverRequest, error) {
	operationDataBytes, err := docutil.MarshalCanonical(opData)
	if err != nil {
		return nil, err
	}

	signedOperationDataBytes, err := docutil.MarshalCanonical(signedOpData)
	if err != nil {
		return nil, err
	}

	return &model.RecoverRequest{
		Operation:       model.OperationTypeRecover,
		DidUniqueSuffix: "suffix",
		OperationData:   docutil.EncodeToString(operationDataBytes),
		SignedOperationData: &model.JWS{
			// TODO: JWS encoded
			Payload: docutil.EncodeToString(signedOperationDataBytes),
		},
	}, nil
}

func getDefaultRecoverRequest() (*model.RecoverRequest, error) {
	return getRecoverRequest(getOperationData(), getSignedOperationData())
}

func getSignedOperationData() *model.SignedOperationDataSchema {
	return &model.SignedOperationDataSchema{
		RecoveryKey:         model.PublicKey{PublicKeyHex: "HEX"},
		NextRecoveryOTPHash: computeMultihash("recoveryOTP"),
		OperationDataHash:   computeMultihash("operation"),
	}
}

func getRecoverRequestBytes() ([]byte, error) {
	req, err := getDefaultRecoverRequest()
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}
