/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
)

const (
	didSuffix = "whatever"
	opaqueDoc = "{}"

	signerErr = "signer error"

	sha2_256 = 18
)

func TestNewCreateRequest(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	require.NoError(t, err)

	t.Run("missing opaque document", func(t *testing.T) {
		request, err := NewCreateRequest(&CreateRequestInfo{})
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing opaque document")
	})
	t.Run("missing recovery key", func(t *testing.T) {
		request, err := NewCreateRequest(&CreateRequestInfo{OpaqueDocument: "{}"})
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing recovery key")
	})
	t.Run("multihash not supported", func(t *testing.T) {
		info := &CreateRequestInfo{OpaqueDocument: "{}",
			RecoveryKey: jwk}

		request, err := NewCreateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "algorithm not supported")
	})
	t.Run("success", func(t *testing.T) {
		info := &CreateRequestInfo{OpaqueDocument: "{}",
			RecoveryKey:   jwk,
			MultihashCode: sha2_256}

		request, err := NewCreateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestNewDeactivateRequest(t *testing.T) {
	t.Run("missing unique suffix", func(t *testing.T) {
		info := &DeactivateRequestInfo{}

		request, err := NewDeactivateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing did unique suffix")
	})
	t.Run("signing error", func(t *testing.T) {
		info := &DeactivateRequestInfo{DidSuffix: "whatever", Signer: NewMockSigner(errors.New(signerErr), true)}

		request, err := NewDeactivateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), signerErr)
	})
	t.Run("success", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(privateKey, "ES256", "")

		info := &DeactivateRequestInfo{DidSuffix: "whatever", Signer: signer}

		request, err := NewDeactivateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestNewUpdateRequest(t *testing.T) {
	const didSuffix = "whatever"

	patch, err := getTestPatch()
	require.NoError(t, err)

	signer := NewMockSigner(nil, false)

	t.Run("missing unique suffix", func(t *testing.T) {
		info := &UpdateRequestInfo{}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing did unique suffix")
	})
	t.Run("missing json patch", func(t *testing.T) {
		info := &UpdateRequestInfo{DidSuffix: didSuffix}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing update information")
	})
	t.Run("multihash not supported", func(t *testing.T) {
		info := &UpdateRequestInfo{
			DidSuffix: didSuffix,
			Patch:     patch,
			Signer:    signer}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "algorithm not supported")
	})
	t.Run("signer has to have kid error", func(t *testing.T) {
		// recovery signer doesn't have kid; update signer has to have it
		info := &UpdateRequestInfo{
			DidSuffix:     didSuffix,
			Patch:         patch,
			MultihashCode: sha2_256,
			Signer:        NewMockSigner(nil, true)}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "kid has to be provided for update signer")
	})
	t.Run("signing error", func(t *testing.T) {
		info := &UpdateRequestInfo{
			DidSuffix:     didSuffix,
			Patch:         patch,
			MultihashCode: sha2_256,
			Signer:        NewMockSigner(errors.New(signerErr), false)}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), signerErr)
	})
	t.Run("success", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(privateKey, "ES256", "key-1")

		info := &UpdateRequestInfo{
			DidSuffix:     didSuffix,
			Patch:         patch,
			MultihashCode: sha2_256,
			Signer:        signer,
		}

		request, err := NewUpdateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func getTestPatch() (patch.Patch, error) {
	return patch.NewJSONPatch(`[{"op": "replace", "path": "/name", "value": "Jane"}]`)
}

func TestNewRecoverRequest(t *testing.T) {
	t.Run("missing unique suffix", func(t *testing.T) {
		info := getRecoverRequestInfo()
		info.DidSuffix = ""

		request, err := NewRecoverRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing did unique suffix")
	})
	t.Run("missing opaque document", func(t *testing.T) {
		info := getRecoverRequestInfo()
		info.OpaqueDocument = ""

		request, err := NewRecoverRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing opaque document")
	})
	t.Run("missing recovery key", func(t *testing.T) {
		info := getRecoverRequestInfo()
		info.RecoveryKey = nil

		request, err := NewRecoverRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing recovery key")
	})
	t.Run("missing signer", func(t *testing.T) {
		info := getRecoverRequestInfo()
		info.Signer = nil

		request, err := NewRecoverRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing signer")
	})
	t.Run("multihash not supported", func(t *testing.T) {
		info := getRecoverRequestInfo()
		info.MultihashCode = 55

		request, err := NewRecoverRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "algorithm not supported")
	})
	t.Run("signing error", func(t *testing.T) {
		info := getRecoverRequestInfo()
		info.Signer = NewMockSigner(errors.New(signerErr), true)

		request, err := NewRecoverRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), signerErr)
	})

	t.Run("success", func(t *testing.T) {
		info := getRecoverRequestInfo()

		bytes, err := NewRecoverRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, bytes)

		var request map[string]interface{}
		err = json.Unmarshal(bytes, &request)
		require.NoError(t, err)

		require.Equal(t, "recover", request["type"])
		require.Equal(t, didSuffix, request["did_suffix"])
	})
}

func TestSignModel(t *testing.T) {
	t.Run("marshal error", func(t *testing.T) {
		ch := make(chan int)
		request, err := signModel(ch, nil)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "unsupported type: chan int")
	})
	t.Run("success", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(privateKey, "ES256", "key-1")

		test := struct {
			message string
		}{
			message: "test",
		}

		request, err := signModel(test, signer)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestSignPayload(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		signer := ecsigner.New(privateKey, "ES256", "key-1")

		message := "test"
		jwsSignature, err := signPayload(message, signer)
		require.NoError(t, err)
		require.NotEmpty(t, jwsSignature)

		_, err = internal.ParseJWS(jwsSignature.Signature, jwk)
		require.NoError(t, err)
	})
	t.Run("signing algorithm required", func(t *testing.T) {
		signer := ecsigner.New(privateKey, "", "kid")

		jws, err := signPayload("test", signer)
		require.Error(t, err)
		require.Empty(t, jws)
		require.Contains(t, err.Error(), "signing algorithm is required")
	})
	t.Run("kid is required", func(t *testing.T) {
		jws, err := signPayload("", NewMockSigner(errors.New("test error"), true))
		require.Error(t, err)
		require.Empty(t, jws)
		require.Contains(t, err.Error(), "test error")
	})
}

func TestValidateSigner(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("success - recovery signer", func(t *testing.T) {
		signer := ecsigner.New(privateKey, "alg", "")

		err := validateSigner(signer, true)
		require.NoError(t, err)
	})
	t.Run("success - update signer (kid has to be provided)", func(t *testing.T) {
		signer := ecsigner.New(privateKey, "alg", "kid")

		err := validateSigner(signer, false)
		require.NoError(t, err)
	})
	t.Run("missing signer", func(t *testing.T) {
		err := validateSigner(nil, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signer")
	})

	t.Run("kid has to be provided for update signer", func(t *testing.T) {
		signer := ecsigner.New(privateKey, "alg", "")

		err := validateSigner(signer, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "kid has to be provided for update signer")
	})

	t.Run("kid must not be provided for recovery signer", func(t *testing.T) {
		signer := ecsigner.New(privateKey, "alg", "kid")

		err := validateSigner(signer, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "kid must not be provided for recovery signer")
	})
}

func getRecoverRequestInfo() *RecoverRequestInfo {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	jwk, err := pubkey.GetPublicKeyJWK(&privKey.PublicKey)
	if err != nil {
		panic(err)
	}

	return &RecoverRequestInfo{
		DidSuffix:      didSuffix,
		OpaqueDocument: opaqueDoc,
		RecoveryKey:    jwk,
		MultihashCode:  sha2_256,
		Signer:         ecsigner.New(privKey, "ES256", "")}
}

// mockSigner implements signer interface
type mockSigner struct {
	Recovery bool
	Err      error
}

// New creates new mock signer (default to recovery signer)
func NewMockSigner(err error, recovery bool) Signer {
	return &mockSigner{Err: err, Recovery: recovery}
}

// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
func (ms *mockSigner) Headers() jws.Headers {
	headers := make(jws.Headers)
	headers[jws.HeaderAlgorithm] = "alg"
	if !ms.Recovery {
		headers[jws.HeaderKeyID] = "kid"
	}

	return headers
}

// Sign signs msg and returns mock signature value
func (ms *mockSigner) Sign(msg []byte) ([]byte, error) {
	if ms.Err != nil {
		return nil, ms.Err
	}

	return []byte("signature"), nil
}
