/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

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
