/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"testing"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

const sha2_256 = 18

func TestNewCreateRequest(t *testing.T) {
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
			RecoveryKey: "recovery"}

		request, err := NewCreateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "algorithm not supported")
	})
	t.Run("next update otp not encoded", func(t *testing.T) {
		info := &CreateRequestInfo{
			OpaqueDocument: "{}",
			RecoveryKey:    "recovery",
			NextUpdateOTP:  "invalid",
			MultihashCode:  sha2_256}

		request, err := NewCreateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "illegal base64 data")
	})
	t.Run("next update otp not encoded", func(t *testing.T) {
		info := &CreateRequestInfo{
			OpaqueDocument:  "{}",
			RecoveryKey:     "recovery",
			NextUpdateOTP:   docutil.EncodeToString([]byte("updateOTP")),
			NextRecoveryOTP: "invalid",
			MultihashCode:   sha2_256,
		}

		request, err := NewCreateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "illegal base64 data")
	})
	t.Run("success", func(t *testing.T) {
		info := &CreateRequestInfo{OpaqueDocument: "{}",
			RecoveryKey: "recovery", MultihashCode: sha2_256}

		request, err := NewCreateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestNewRevokeRequest(t *testing.T) {
	t.Run("missing unique suffix", func(t *testing.T) {
		info := &RevokeRequestInfo{}

		request, err := NewRevokeRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing did unique suffix")
	})
	t.Run("success", func(t *testing.T) {
		info := &RevokeRequestInfo{DidUniqueSuffix: "whatever"}

		request, err := NewRevokeRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestNewUpdatePayload(t *testing.T) {
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

	t.Run("next update otp not encoded", func(t *testing.T) {
		info := &UpdateRequestInfo{DidUniqueSuffix: didUniqueSuffix, Patch: patch, NextUpdateOTP: "invalid"}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "illegal base64 data")
	})

	t.Run("success", func(t *testing.T) {
		info := &UpdateRequestInfo{DidUniqueSuffix: didUniqueSuffix, Patch: patch, MultihashCode: sha2_256}

		request, err := NewUpdateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func getTestPatch() (jsonpatch.Patch, error) {
	patchJSON := []byte(`[
		{"op": "replace", "path": "/name", "value": "Jane"}
	]`)

	return jsonpatch.DecodePatch(patchJSON)
}
