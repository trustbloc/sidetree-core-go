/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

const sha2_256 = 18

func TestParseDeactivateOperation(t *testing.T) {
	p := protocol.Protocol{
		MultihashAlgorithms:    []uint{sha2_256},
		MaxOperationHashLength: maxHashLength,
		SignatureAlgorithms:    []string{"alg"},
		KeyAlgorithms:          []string{"crv"},
		MaxOperationTimeDelta:  5 * 60,
	}

	parser := New(p)

	t.Run("success", func(t *testing.T) {
		payload, err := getDeactivateRequestBytes()
		require.NoError(t, err)

		op, err := parser.ParseDeactivateOperation(payload, false)
		require.NoError(t, err)
		require.Equal(t, operation.TypeDeactivate, op.Type)

		signedData, err := parser.ParseSignedDataForDeactivate(op.SignedData)
		expectedRevealValue, err := commitment.GetRevealValue(signedData.RecoveryKey, sha2_256)
		require.NoError(t, err)

		require.Equal(t, expectedRevealValue, op.RevealValue)
	})

	t.Run("success - anchor until default to anchor from + max operation time delta protocol param", func(t *testing.T) {
		now := time.Now().Unix()

		signedData := &model.DeactivateSignedDataModel{
			DidSuffix: "did",
			RecoveryKey: &jws.JWK{
				Kty: "kty",
				Crv: "crv",
				X:   "x",
			},
			AnchorFrom: now - 5*60,
		}

		deactivateRequest, err := getDeactivateRequest(signedData)
		require.NoError(t, err)

		reqBytes, err := json.Marshal(deactivateRequest)
		require.NoError(t, err)

		op, err := parser.ParseDeactivateOperation(reqBytes, false)
		require.NoError(t, err)
		require.NotEmpty(t, op)
	})

	t.Run("missing unique suffix", func(t *testing.T) {
		schema, err := parser.ParseDeactivateOperation([]byte("{}"), false)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "missing did suffix")
	})
	t.Run("missing signed data", func(t *testing.T) {
		op, err := parser.ParseDeactivateOperation([]byte(`{"didSuffix":"abc"}`), false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signed data")
		require.Nil(t, op)
	})
	t.Run("parse request", func(t *testing.T) {
		request, err := json.Marshal("invalidJSON")
		require.NoError(t, err)

		op, err := parser.ParseDeactivateOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot unmarshal string")
		require.Nil(t, op)
	})
	t.Run("parse signed data error - decoding failed", func(t *testing.T) {
		deactivateRequest, err := getDefaultDeactivateRequest()
		require.NoError(t, err)

		deactivateRequest.SignedData = "invalid"
		request, err := json.Marshal(deactivateRequest)
		require.NoError(t, err)

		op, err := parser.ParseDeactivateOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid JWS compact format")
		require.Nil(t, op)
	})
	t.Run("validate signed data error - did suffix mismatch", func(t *testing.T) {
		signedData := getSignedDataForDeactivate()
		signedData.DidSuffix = "different"

		recoverRequest, err := getDeactivateRequest(signedData)
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := parser.ParseDeactivateOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signed did suffix mismatch for deactivate")
		require.Nil(t, op)
	})
	t.Run("parse signed data error - unmarshal signed data failed", func(t *testing.T) {
		deactivateRequest, err := getDefaultDeactivateRequest()
		require.NoError(t, err)

		compactJWS, err := signutil.SignPayload([]byte("payload"), NewMockSigner())
		require.NoError(t, err)

		deactivateRequest.SignedData = compactJWS
		request, err := json.Marshal(deactivateRequest)
		require.NoError(t, err)

		op, err := parser.ParseDeactivateOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for deactivate")
		require.Nil(t, op)
	})
	t.Run("error - key algorithm not supported", func(t *testing.T) {
		p := protocol.Protocol{
			MultihashAlgorithms:    []uint{sha2_256},
			MaxOperationHashLength: maxHashLength,
			SignatureAlgorithms:    []string{"alg"},
			KeyAlgorithms:          []string{"other"},
		}
		parser := New(p)

		request, err := getDeactivateRequestBytes()
		require.NoError(t, err)

		op, err := parser.ParseDeactivateOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "validate signed data for deactivate: key algorithm 'crv' is not in the allowed list [other]")
		require.Nil(t, op)
	})
}

func TestValidateDeactivateRequest(t *testing.T) {
	parser := New(protocol.Protocol{MaxOperationHashLength: maxHashLength, MultihashAlgorithms: []uint{sha2_256}})

	t.Run("success", func(t *testing.T) {
		deactivate, err := getDefaultDeactivateRequest()
		require.NoError(t, err)

		err = parser.validateDeactivateRequest(deactivate)
		require.NoError(t, err)
	})
	t.Run("missing signed data", func(t *testing.T) {
		deactivate, err := getDefaultDeactivateRequest()
		require.NoError(t, err)
		deactivate.SignedData = ""

		err = parser.validateDeactivateRequest(deactivate)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signed data")
	})
	t.Run("missing did suffix", func(t *testing.T) {
		deactivate, err := getDefaultDeactivateRequest()
		require.NoError(t, err)
		deactivate.DidSuffix = ""

		err = parser.validateDeactivateRequest(deactivate)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing did suffix")
	})

	t.Run("invalid reveal value", func(t *testing.T) {
		deactivate, err := getDefaultDeactivateRequest()
		require.NoError(t, err)
		deactivate.RevealValue = "invalid"

		err = parser.validateDeactivateRequest(deactivate)
		require.Error(t, err)
		require.Contains(t, err.Error(), "reveal value is not computed with the required hash algorithms: [18]")
	})
}

func getDeactivateRequest(signedData *model.DeactivateSignedDataModel) (*model.DeactivateRequest, error) {
	compactJWS, err := signutil.SignModel(signedData, NewMockSigner())
	if err != nil {
		return nil, err
	}

	revealValue, err := hashing.CalculateModelMultihash(signedData.RecoveryKey, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.DeactivateRequest{
		Operation:   operation.TypeDeactivate,
		DidSuffix:   "did",
		SignedData:  compactJWS,
		RevealValue: revealValue,
	}, nil
}

func getDefaultDeactivateRequest() (*model.DeactivateRequest, error) {
	return getDeactivateRequest(getSignedDataForDeactivate())
}

func getSignedDataForDeactivate() *model.DeactivateSignedDataModel {
	return &model.DeactivateSignedDataModel{
		DidSuffix: "did",
		RecoveryKey: &jws.JWK{
			Kty: "kty",
			Crv: "crv",
			X:   "x",
		},
	}
}

func getDeactivateRequestBytes() ([]byte, error) {
	req, err := getDeactivateRequest(getSignedDataForDeactivate())
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}
