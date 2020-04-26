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
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
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
	t.Run("validate recover request", func(t *testing.T) {
		recoverRequest, err := getDefaultRecoverRequest()
		require.NoError(t, err)

		recoverRequest.DidSuffix = ""
		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "missing did suffix")
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

func TestValidateSignedDataForRecovery(t *testing.T) {
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

func TestValidateSignedData(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		signedData := &model.JWS{
			Protected: &model.Header{
				Alg: "alg",
				Kid: "kid",
			},
			Payload:   "payload",
			Signature: "signature",
		}

		err := validateSignedData(signedData)
		require.NoError(t, err)
	})
	t.Run("missing signed data", func(t *testing.T) {
		err := validateSignedData(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signed data")
	})
	t.Run("missing protected header", func(t *testing.T) {
		signedData := &model.JWS{
			Payload:   "payload",
			Signature: "signature",
		}

		err := validateSignedData(signedData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signed data is missing protected header")
	})
	t.Run("missing payload", func(t *testing.T) {
		signedData := &model.JWS{
			Protected: &model.Header{
				Alg: "alg",
				Kid: "kid",
			},
			Signature: "signature",
		}

		err := validateSignedData(signedData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signed data is missing payload")
	})
	t.Run("missing signature", func(t *testing.T) {
		signedData := &model.JWS{
			Protected: &model.Header{
				Alg: "alg",
				Kid: "kid",
			},
			Payload: "payload",
		}

		err := validateSignedData(signedData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signed data is missing signature")
	})
	t.Run("missing algorithm", func(t *testing.T) {
		signedData := &model.JWS{
			Protected: &model.Header{
				Kid: "kid",
			},
			Payload:   "payload",
			Signature: "signature",
		}

		err := validateSignedData(signedData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing algorithm in protected header")
	})
}

func TestValidateRecoverRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		recover, err := getDefaultRecoverRequest()
		require.NoError(t, err)

		err = validateRecoverRequest(recover)
		require.NoError(t, err)
	})
	t.Run("missing signed data", func(t *testing.T) {
		recover, err := getDefaultRecoverRequest()
		require.NoError(t, err)
		recover.SignedData = nil

		err = validateRecoverRequest(recover)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signed data")
	})
	t.Run("missing did suffix", func(t *testing.T) {
		recover, err := getDefaultRecoverRequest()
		require.NoError(t, err)
		recover.DidSuffix = ""

		err = validateRecoverRequest(recover)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing did suffix")
	})
	t.Run("missing delta", func(t *testing.T) {
		recover, err := getDefaultRecoverRequest()
		require.NoError(t, err)
		recover.Delta = ""

		err = validateRecoverRequest(recover)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing delta")
	})
}

func getRecoverRequest(delta *model.DeltaModel, signedData *model.RecoverSignedDataModel) (*model.RecoverRequest, error) {
	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	signedDataBytes, err := canonicalizer.MarshalCanonical(signedData)
	if err != nil {
		return nil, err
	}

	return &model.RecoverRequest{
		Operation: model.OperationTypeRecover,
		DidSuffix: "suffix",
		Delta:     docutil.EncodeToString(deltaBytes),
		SignedData: &model.JWS{
			Protected: &model.Header{
				Alg: "alg",
				Kid: "kid",
			},
			Payload:   docutil.EncodeToString(signedDataBytes),
			Signature: "signature",
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
		RecoveryKey: &jws.JWK{
			Kty: "kty",
			Crv: "crv",
			X:   "x",
		},
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
