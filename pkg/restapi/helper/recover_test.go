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

	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
)

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
		require.Equal(t, didSuffix, request["did_suffix"])
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
