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
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
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

		recoverRequest.SignedData = invalid
		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid JWS compact format")
		require.Nil(t, op)
	})
	t.Run("parse signed data error - unmarshal failed", func(t *testing.T) {
		recoverRequest, err := getDefaultRecoverRequest()
		require.NoError(t, err)

		compactJWS, err := signutil.SignPayload([]byte("payload"), NewMockSigner())
		require.NoError(t, err)

		recoverRequest.SignedData = compactJWS
		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := ParseRecoverOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for recover")
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
		require.Contains(t, err.Error(), "signed data for recovery: missing key")
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
			"signed data for recovery: missing key")
	})
	t.Run("invalid patch data hash", func(t *testing.T) {
		signed := getSignedDataForRecovery()
		signed.DeltaHash = ""
		err := validateSignedDataForRecovery(signed, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "patch data hash is not computed with the required hash algorithm")
	})
	t.Run("invalid next recovery commitment hash", func(t *testing.T) {
		signed := getSignedDataForRecovery()
		signed.RecoveryCommitment = ""
		err := validateSignedDataForRecovery(signed, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery commitment hash is not computed with the required hash algorithm")
	})
}

func TestParseSignedData(t *testing.T) {
	mockSigner := NewMockSigner()

	t.Run("success", func(t *testing.T) {
		jwsSignature, err := internal.NewJWS(nil, nil, []byte("payload"), mockSigner)
		require.NoError(t, err)

		compactJWS, err := jwsSignature.SerializeCompact(false)
		require.NoError(t, err)

		jws, err := parseSignedData(compactJWS)
		require.NoError(t, err)
		require.NotNil(t, jws)
	})
	t.Run("missing signed data", func(t *testing.T) {
		jws, err := parseSignedData("")
		require.Error(t, err)
		require.Nil(t, jws)
		require.Contains(t, err.Error(), "missing signed data")
	})
	t.Run("missing protected headers", func(t *testing.T) {
		jws, err := parseSignedData(".cGF5bG9hZA.c2lnbmF0dXJl")
		require.Error(t, err)
		require.Nil(t, jws)
		require.Contains(t, err.Error(), "unmarshal JSON headers: unexpected end of JSON input")
	})
	t.Run("missing payload", func(t *testing.T) {
		jwsSignature, err := internal.NewJWS(nil, nil, nil, mockSigner)
		require.NoError(t, err)

		compactJWS, err := jwsSignature.SerializeCompact(false)
		require.NoError(t, err)

		jws, err := parseSignedData(compactJWS)
		require.Error(t, err)
		require.Nil(t, jws)
		require.Contains(t, err.Error(), "compact jws payload is empty")
	})
	t.Run("missing signature", func(t *testing.T) {
		jws, err := parseSignedData("eyJhbGciOiJhbGciLCJraWQiOiJraWQifQ.cGF5bG9hZA.")
		require.Error(t, err)
		require.Nil(t, jws)
		require.Contains(t, err.Error(), "compact jws signature is empty")
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
		recover.SignedData = ""

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

	compactJWS, err := signutil.SignModel(signedData, NewMockSigner())
	if err != nil {
		return nil, err
	}

	return &model.RecoverRequest{
		Operation:  model.OperationTypeRecover,
		DidSuffix:  "suffix",
		Delta:      docutil.EncodeToString(deltaBytes),
		SignedData: compactJWS,
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
		RecoveryCommitment: computeMultihash([]byte("recoveryReveal")),
		DeltaHash:          computeMultihash([]byte("operation")),
	}
}

func getRecoverRequestBytes() ([]byte, error) {
	req, err := getDefaultRecoverRequest()
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}

// MockSigner implements signer interface
type MockSigner struct {
	MockSignature []byte
	MockHeaders   jws.Headers
	Err           error
}

// New creates new mock signer (default to recovery signer)
func NewMockSigner() *MockSigner {
	headers := make(jws.Headers)
	headers[jws.HeaderAlgorithm] = "alg"
	headers[jws.HeaderKeyID] = "kid"

	return &MockSigner{MockHeaders: headers, MockSignature: []byte("signature")}
}

// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
func (ms *MockSigner) Headers() jws.Headers {
	return ms.MockHeaders
}

// Sign signs msg and returns mock signature value
func (ms *MockSigner) Sign(msg []byte) ([]byte, error) {
	if ms.Err != nil {
		return nil, ms.Err
	}

	return ms.MockSignature, nil
}
