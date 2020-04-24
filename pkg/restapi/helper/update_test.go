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

	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
)

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
