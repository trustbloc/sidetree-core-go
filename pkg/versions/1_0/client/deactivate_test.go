/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
)

func TestNewDeactivateRequest(t *testing.T) {
	t.Run("missing unique suffix", func(t *testing.T) {
		info := &DeactivateRequestInfo{}

		request, err := NewDeactivateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing did unique suffix")
	})
	t.Run("missing reveal value", func(t *testing.T) {
		info := &DeactivateRequestInfo{DidSuffix: "suffix"}

		request, err := NewDeactivateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing reveal value")
	})
	t.Run("signing error", func(t *testing.T) {
		info := &DeactivateRequestInfo{
			DidSuffix:   "whatever",
			Signer:      NewMockSigner(errors.New(signerErr)),
			RevealValue: "reveal",
		}

		request, err := NewDeactivateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), signerErr)
	})
	t.Run("success", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		signer := ecsigner.New(privateKey, "ES256", "")

		info := &DeactivateRequestInfo{
			DidSuffix:   "whatever",
			Signer:      signer,
			RecoveryKey: jwk,
			RevealValue: "reveal",
		}

		request, err := NewDeactivateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestValidateSigner(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const testKid = "kid"

	t.Run("success - kid can be empty", func(t *testing.T) {
		signer := ecsigner.New(privateKey, "alg", "")

		err := validateSigner(signer)
		require.NoError(t, err)
	})
	t.Run("success - kid can be provided", func(t *testing.T) {
		signer := ecsigner.New(privateKey, "alg", testKid)

		err := validateSigner(signer)
		require.NoError(t, err)
	})
	t.Run("error - missing signer", func(t *testing.T) {
		err := validateSigner(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signer")
	})

	t.Run("error - missing protected headers", func(t *testing.T) {
		err := validateSigner(&MockSigner{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing protected headers")
	})

	t.Run("err - algorithm must be present in the protected header", func(t *testing.T) {
		headers := make(jws.Headers)

		headers["kid"] = testKid

		signer := &MockSigner{MockHeaders: headers}

		err := validateSigner(signer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "algorithm must be present in the protected header")
	})

	t.Run("err - algorithm cannot be empty", func(t *testing.T) {
		headers := make(jws.Headers)

		headers["kid"] = testKid
		headers["alg"] = ""

		signer := &MockSigner{MockHeaders: headers}

		err := validateSigner(signer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "algorithm cannot be empty in the protected header")
	})

	t.Run("err - invalid protected header value", func(t *testing.T) {
		headers := make(jws.Headers)

		headers["kid"] = "kid"
		headers["alg"] = "alg"
		headers["invalid"] = "value"

		signer := &MockSigner{MockHeaders: headers}

		err := validateSigner(signer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "header 'invalid' is not allowed in the protected headers")
	})
}

// MockSigner implements signer interface.
type MockSigner struct {
	MockHeaders jws.Headers
	Err         error
}

// New creates new mock signer (default to recovery signer).
func NewMockSigner(err error) *MockSigner {
	headers := make(jws.Headers)
	headers[jws.HeaderAlgorithm] = "alg"
	headers[jws.HeaderKeyID] = "kid"

	return &MockSigner{Err: err, MockHeaders: headers}
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

	return []byte("signature"), nil
}
