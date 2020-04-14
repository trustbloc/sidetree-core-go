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
	didUniqueSuffix = "whatever"
	opaqueDoc       = "{}"

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
		info := &DeactivateRequestInfo{DidUniqueSuffix: "whatever", Signer: NewMockSigner(errors.New(signerErr))}

		request, err := NewDeactivateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), signerErr)
	})
	t.Run("success", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(privateKey, "ES256", "recovery")

		info := &DeactivateRequestInfo{DidUniqueSuffix: "whatever", Signer: signer}

		request, err := NewDeactivateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestNewUpdateRequest(t *testing.T) {
	const didUniqueSuffix = "whatever"

	patch, err := getTestPatch()
	require.NoError(t, err)

	t.Run("missing unique suffix", func(t *testing.T) {
		info := &UpdateRequestInfo{}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing did unique suffix")
	})
	t.Run("missing json patch", func(t *testing.T) {
		info := &UpdateRequestInfo{DidUniqueSuffix: didUniqueSuffix}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing update information")
	})
	t.Run("multihash not supported", func(t *testing.T) {
		info := &UpdateRequestInfo{DidUniqueSuffix: didUniqueSuffix, Patch: patch}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "algorithm not supported")
	})
	t.Run("signing error", func(t *testing.T) {
		info := &UpdateRequestInfo{
			DidUniqueSuffix: didUniqueSuffix,
			Patch:           patch,
			MultihashCode:   sha2_256,
			Signer:          NewMockSigner(errors.New(signerErr))}

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
			DidUniqueSuffix: didUniqueSuffix,
			Patch:           patch,
			MultihashCode:   sha2_256,
			Signer:          signer,
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
		info.DidUniqueSuffix = ""

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
		info.Signer = NewMockSigner(errors.New(signerErr))

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
		require.Equal(t, didUniqueSuffix, request["didUniqueSuffix"])
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
		signer := ecsigner.New(privateKey, "alg", "")

		jws, err := signPayload("test", signer)
		require.Error(t, err)
		require.Empty(t, jws)
		require.Contains(t, err.Error(), "signing kid is required")
	})
	t.Run("kid is required", func(t *testing.T) {
		jws, err := signPayload("", NewMockSigner(errors.New("test error")))
		require.Error(t, err)
		require.Empty(t, jws)
		require.Contains(t, err.Error(), "test error")
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
		DidUniqueSuffix: didUniqueSuffix,
		OpaqueDocument:  opaqueDoc,
		RecoveryKey:     jwk,
		MultihashCode:   sha2_256,
		Signer:          ecsigner.New(privKey, "ES256", "recovery")}
}

// mockSigner implements signer interface
type mockSigner struct {
	Err error
}

// New creates new mock signer
func NewMockSigner(err error) Signer {
	return &mockSigner{Err: err}
}

// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
func (ms *mockSigner) Headers() jws.Headers {
	headers := make(jws.Headers)
	headers[jws.HeaderKeyID] = "kid"
	headers[jws.HeaderAlgorithm] = "alg"

	return headers
}

// Sign signs msg and returns mock signature value
func (ms *mockSigner) Sign(msg []byte) ([]byte, error) {
	if ms.Err != nil {
		return nil, ms.Err
	}

	return []byte("signature"), nil
}
