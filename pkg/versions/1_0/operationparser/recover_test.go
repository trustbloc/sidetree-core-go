/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
)

const (
	kidKey = "kid"
	algKey = "alg"
)

func TestParseRecoverOperation(t *testing.T) {
	p := protocol.Protocol{
		MaxOperationHashLength: maxHashLength,
		MaxDeltaSize:           maxDeltaSize,
		MultihashAlgorithms:    []uint{sha2_256},
		SignatureAlgorithms:    []string{"alg"},
		KeyAlgorithms:          []string{"crv"},
		Patches:                []string{"add-public-keys", "remove-public-keys", "add-services", "remove-services", "ietf-json-patch"},
	}

	parser := New(p)

	t.Run("success", func(t *testing.T) {
		request, err := getRecoverRequestBytes()
		require.NoError(t, err)

		op, err := parser.ParseRecoverOperation(request, false)
		require.NoError(t, err)
		require.Equal(t, operation.TypeRecover, op.Type)

		signedData, err := parser.ParseSignedDataForRecover(op.SignedData)
		expectedRevealValue, err := commitment.GetRevealValue(signedData.RecoveryKey, sha2_256)
		require.NoError(t, err)

		require.Equal(t, expectedRevealValue, op.RevealValue)
	})
	t.Run("parse recover request error", func(t *testing.T) {
		schema, err := parser.ParseRecoverOperation([]byte(""), false)
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

		op, err := parser.ParseRecoverOperation(request, false)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "missing did suffix")
	})
	t.Run("parse patch data error", func(t *testing.T) {
		recoverRequest, err := getDefaultRecoverRequest()
		require.NoError(t, err)

		recoverRequest.Delta = &model.DeltaModel{}
		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := parser.ParseRecoverOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing patches")
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

		op, err := parser.ParseRecoverOperation(request, false)
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

		op, err := parser.ParseRecoverOperation(request, false)
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

		op, err := parser.ParseRecoverOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for recover")
		require.Nil(t, op)
	})
	t.Run("validate signed data error", func(t *testing.T) {
		signedData := getSignedDataForRecovery()
		signedData.RecoveryKey = &jws.JWK{}

		delta, err := getDelta()
		require.NoError(t, err)

		recoverRequest, err := getRecoverRequest(delta, signedData)
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := parser.ParseRecoverOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "validate signed data for recovery: signing key validation failed: JWK crv is missing")
		require.Nil(t, op)
	})

	t.Run("error - update commitment equals recovery commitment", func(t *testing.T) {
		signedData := getSignedDataForRecovery()

		delta, err := getDelta()
		require.NoError(t, err)

		delta.UpdateCommitment = signedData.RecoveryCommitment
		recoverRequest, err := getRecoverRequest(delta, signedData)
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := parser.ParseRecoverOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "recovery and update commitments cannot be equal, re-using public keys is not allowed")
		require.Nil(t, op)
	})

	t.Run("error - current commitment cannot equal recovery commitment", func(t *testing.T) {
		signedData := getSignedDataForRecovery()

		recoveryCommitment, err := commitment.GetCommitment(signedData.RecoveryKey, sha2_256)
		require.NoError(t, err)

		signedData.RecoveryCommitment = recoveryCommitment

		delta, err := getDelta()
		require.NoError(t, err)

		recoverRequest, err := getRecoverRequest(delta, signedData)
		require.NoError(t, err)

		request, err := json.Marshal(recoverRequest)
		require.NoError(t, err)

		op, err := parser.ParseRecoverOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "re-using public keys for commitment is not allowed")
		require.Nil(t, op)
	})
}

func TestValidateSignedDataForRecovery(t *testing.T) {
	p := protocol.Protocol{
		MaxOperationHashLength: maxHashLength,
		MultihashAlgorithms:    []uint{sha2_256},
		KeyAlgorithms:          []string{"crv"},
	}

	parser := New(p)

	t.Run("success", func(t *testing.T) {
		signed := getSignedDataForRecovery()
		err := parser.validateSignedDataForRecovery(signed)
		require.NoError(t, err)
	})
	t.Run("invalid patch data hash", func(t *testing.T) {
		signed := getSignedDataForRecovery()
		signed.DeltaHash = ""
		err := parser.validateSignedDataForRecovery(signed)
		require.Error(t, err)
		require.Contains(t, err.Error(), "delta hash is not computed with the required hash algorithms: [18]")
	})
	t.Run("invalid next recovery commitment hash", func(t *testing.T) {
		signed := getSignedDataForRecovery()
		signed.RecoveryCommitment = ""
		err := parser.validateSignedDataForRecovery(signed)
		require.Error(t, err)
		require.Contains(t, err.Error(), "recovery commitment is not computed with the required hash algorithms: [18]")
	})
	t.Run("recovery commitment exceeds maximum hash length", func(t *testing.T) {
		lowMaxHashLength := protocol.Protocol{
			MaxOperationHashLength: 10,
			MultihashAlgorithms:    []uint{sha2_256},
			KeyAlgorithms:          []string{"crv"},
		}

		signed := getSignedDataForRecovery()

		err := New(lowMaxHashLength).validateSignedDataForRecovery(signed)
		require.Error(t, err)
		require.Contains(t, err.Error(), "recovery commitment length[46] exceeds maximum hash length[10]")
	})
}

func TestParseSignedData(t *testing.T) {
	mockSigner := NewMockSigner()

	p := protocol.Protocol{
		MultihashAlgorithms: []uint{sha2_256},
		SignatureAlgorithms: []string{"alg"},
	}

	parser := New(p)

	t.Run("success", func(t *testing.T) {
		jwsSignature, err := internal.NewJWS(nil, nil, []byte("payload"), mockSigner)
		require.NoError(t, err)

		compactJWS, err := jwsSignature.SerializeCompact(false)
		require.NoError(t, err)

		jws, err := parser.parseSignedData(compactJWS)
		require.NoError(t, err)
		require.NotNil(t, jws)
	})
	t.Run("missing signed data", func(t *testing.T) {
		jws, err := parser.parseSignedData("")
		require.Error(t, err)
		require.Nil(t, jws)
		require.Contains(t, err.Error(), "missing signed data")
	})
	t.Run("missing protected headers", func(t *testing.T) {
		jws, err := parser.parseSignedData(".cGF5bG9hZA.c2lnbmF0dXJl")
		require.Error(t, err)
		require.Nil(t, jws)
		require.Contains(t, err.Error(), "unmarshal JSON headers: unexpected end of JSON input")
	})
	t.Run("missing payload", func(t *testing.T) {
		jwsSignature, err := internal.NewJWS(nil, nil, nil, mockSigner)
		require.NoError(t, err)

		compactJWS, err := jwsSignature.SerializeCompact(false)
		require.NoError(t, err)

		jws, err := parser.parseSignedData(compactJWS)
		require.Error(t, err)
		require.Nil(t, jws)
		require.Contains(t, err.Error(), "compact jws payload is empty")
	})
	t.Run("missing signature", func(t *testing.T) {
		jws, err := parser.parseSignedData("eyJhbGciOiJhbGciLCJraWQiOiJraWQifQ.cGF5bG9hZA.")
		require.Error(t, err)
		require.Nil(t, jws)
		require.Contains(t, err.Error(), "compact jws signature is empty")
	})
	t.Run("error - invalid signing algorithm", func(t *testing.T) {
		jwsSignature, err := internal.NewJWS(nil, nil, []byte("payload"), mockSigner)
		require.NoError(t, err)

		compactJWS, err := jwsSignature.SerializeCompact(false)
		require.NoError(t, err)

		parser := New(protocol.Protocol{
			SignatureAlgorithms: []string{"other"},
		})

		jws, err := parser.parseSignedData(compactJWS)
		require.Error(t, err)
		require.Nil(t, jws)
		require.Contains(t, err.Error(), "failed to parse signed data: algorithm 'alg' is not in the allowed list [other]")
	})
}

func TestValidateSigningKey(t *testing.T) {
	testJWK := &jws.JWK{
		Kty: "kty",
		Crv: "crv",
		X:   "x",
	}

	parser := New(protocol.Protocol{KeyAlgorithms: []string{"crv"}, NonceSize: 16})

	t.Run("success", func(t *testing.T) {
		err := parser.validateSigningKey(testJWK)
		require.NoError(t, err)
	})

	t.Run("error - required info is missing (kty)", func(t *testing.T) {
		err := parser.validateSigningKey(&jws.JWK{
			Crv: "crv",
			X:   "x",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "signing key validation failed: JWK kty is missing")
	})

	t.Run("error - key algorithm not supported", func(t *testing.T) {
		err := New(protocol.Protocol{KeyAlgorithms: []string{"other"}}).validateSigningKey(testJWK)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key algorithm 'crv' is not in the allowed list [other]")
	})

	t.Run("error - failed to decode signing key nonce", func(t *testing.T) {
		nonceJWK := &jws.JWK{
			Kty:   "kty",
			Crv:   "crv",
			X:     "x",
			Nonce: "nonce",
		}

		err := parser.validateSigningKey(nonceJWK)
		require.Error(t, err)
		require.Contains(t, err.Error(), "validate signing key nonce: failed to decode nonce 'nonce': illegal base64 data")
	})

	t.Run("error - failed to validate nonce size", func(t *testing.T) {
		nonceJWK := &jws.JWK{
			Kty:   "kty",
			Crv:   "crv",
			X:     "x",
			Nonce: encoder.EncodeToString([]byte("nonce")),
		}

		err := parser.validateSigningKey(nonceJWK)
		require.Error(t, err)
		require.Contains(t, err.Error(), "validate signing key nonce: nonce size '5' doesn't match configured nonce size '16'")
	})

	t.Run("success - valid nonce size", func(t *testing.T) {
		nonceJWK := &jws.JWK{
			Kty:   "kty",
			Crv:   "crv",
			X:     "x",
			Nonce: encoder.EncodeToString([]byte("nonce")),
		}

		parserWithNonceSize := New(protocol.Protocol{
			KeyAlgorithms: []string{"crv"},
			NonceSize:     5,
		})

		err := parserWithNonceSize.validateSigningKey(nonceJWK)
		require.NoError(t, err)
	})
}

func TestValidateRecoverRequest(t *testing.T) {
	parser := New(protocol.Protocol{MaxOperationHashLength: maxHashLength, MultihashAlgorithms: []uint{sha2_256}})

	t.Run("success", func(t *testing.T) {
		recover, err := getDefaultRecoverRequest()
		require.NoError(t, err)

		err = parser.validateRecoverRequest(recover)
		require.NoError(t, err)
	})
	t.Run("missing signed data", func(t *testing.T) {
		recover, err := getDefaultRecoverRequest()
		require.NoError(t, err)
		recover.SignedData = ""

		err = parser.validateRecoverRequest(recover)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signed data")
	})
	t.Run("missing did suffix", func(t *testing.T) {
		recover, err := getDefaultRecoverRequest()
		require.NoError(t, err)
		recover.DidSuffix = ""

		err = parser.validateRecoverRequest(recover)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing did suffix")
	})

	t.Run("invalid reveal value", func(t *testing.T) {
		recover, err := getDefaultRecoverRequest()
		require.NoError(t, err)
		recover.RevealValue = "reveal"

		err = parser.validateRecoverRequest(recover)
		require.Error(t, err)
		require.Contains(t, err.Error(), "reveal value is not computed with the required hash algorithms: [18]")
	})
}

func TestValidateProtectedHeader(t *testing.T) {
	algs := []string{"alg-1", "alg-2"}

	parser := New(protocol.Protocol{})

	t.Run("success - kid can be empty", func(t *testing.T) {
		protected := getHeaders("alg-1", "")

		err := parser.validateProtectedHeaders(protected, algs)
		require.NoError(t, err)
	})
	t.Run("success - kid can be provided", func(t *testing.T) {
		protected := getHeaders("alg-1", "kid-1")

		err := parser.validateProtectedHeaders(protected, algs)
		require.NoError(t, err)
	})
	t.Run("error - missing header", func(t *testing.T) {
		err := parser.validateProtectedHeaders(nil, algs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing protected headers")
	})

	t.Run("err - algorithm must be present in the protected header", func(t *testing.T) {
		protected := make(jws.Headers)
		protected[kidKey] = "kid-1"

		err := parser.validateProtectedHeaders(protected, algs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "algorithm must be present in the protected header")
	})

	t.Run("err - algorithm cannot be empty", func(t *testing.T) {
		protected := getHeaders("", "kid-1")

		err := parser.validateProtectedHeaders(protected, algs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "algorithm cannot be empty in the protected header")
	})

	t.Run("err - invalid protected header value", func(t *testing.T) {
		protected := make(jws.Headers)

		protected["kid"] = "kid"
		protected["alg"] = "alg"
		protected["other"] = "value"

		err := parser.validateProtectedHeaders(protected, algs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid protected header: other")
	})
	t.Run("error - algorithm not allowed", func(t *testing.T) {
		protected := getHeaders("alg-other", "kid")

		err := parser.validateProtectedHeaders(protected, algs)
		require.Error(t, err)
		require.Equal(t, "algorithm 'alg-other' is not in the allowed list [alg-1 alg-2]", err.Error())
	})
}

func getHeaders(alg, kid string) jws.Headers {
	header := make(jws.Headers)
	header[algKey] = alg
	header[kidKey] = kid

	return header
}

func getRecoverRequest(delta *model.DeltaModel, signedData *model.RecoverSignedDataModel) (*model.RecoverRequest, error) {
	compactJWS, err := signutil.SignModel(signedData, NewMockSigner())
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(signedData.RecoveryKey, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.RecoverRequest{
		Operation:   operation.TypeRecover,
		DidSuffix:   "suffix",
		Delta:       delta,
		SignedData:  compactJWS,
		RevealValue: rv,
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

// MockSigner implements signer interface.
type MockSigner struct {
	MockSignature []byte
	MockHeaders   jws.Headers
	Err           error
}

// New creates new mock signer (default to recovery signer).
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

// Sign signs msg and returns mock signature value.
func (ms *MockSigner) Sign(msg []byte) ([]byte, error) {
	if ms.Err != nil {
		return nil, ms.Err
	}

	return ms.MockSignature, nil
}
