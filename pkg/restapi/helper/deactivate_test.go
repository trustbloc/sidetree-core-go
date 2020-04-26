/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
)

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
