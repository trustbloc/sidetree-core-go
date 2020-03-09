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
	t.Run("success", func(t *testing.T) {
		info := &CreateRequestInfo{OpaqueDocument: "{}",
			RecoveryKey: "recovery", MultihashCode: sha2_256}

		request, err := NewCreateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestNewDeletePayload(t *testing.T) {
	t.Run("missing unique suffix", func(t *testing.T) {
		info := &DeletePayloadInfo{}

		request, err := NewDeletePayload(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing did unique suffix")
	})
	t.Run("success", func(t *testing.T) {
		info := &DeletePayloadInfo{DidUniqueSuffix: "whatever"}

		request, err := NewDeletePayload(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestNewUpdatePayload(t *testing.T) {
	const didUniqueSuffix = "whatever"
	patch, err := getTestPatch()
	require.NoError(t, err)

	t.Run("missing unique suffix", func(t *testing.T) {
		info := &UpdatePayloadInfo{}

		request, err := NewUpdatePayload(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing did unique suffix")
	})
	t.Run("missing json patch", func(t *testing.T) {
		info := &UpdatePayloadInfo{DidUniqueSuffix: didUniqueSuffix}

		request, err := NewUpdatePayload(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing update information")
	})

	t.Run("multihash not supported", func(t *testing.T) {
		info := &UpdatePayloadInfo{DidUniqueSuffix: didUniqueSuffix, Patch: patch}

		request, err := NewUpdatePayload(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "algorithm not supported")
	})

	t.Run("success", func(t *testing.T) {
		info := &UpdatePayloadInfo{DidUniqueSuffix: didUniqueSuffix, Patch: patch, MultihashCode: sha2_256}

		request, err := NewUpdatePayload(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestNewRequest(t *testing.T) {
	create, err := NewCreateRequest(&CreateRequestInfo{
		OpaqueDocument:  "{}",
		RecoveryKey:     "recovery",
		NextRecoveryOTP: "recoveryOTP",
		NextUpdateOTP:   "updateOTP",
		MultihashCode:   sha2_256,
	})
	require.NoError(t, err)
	require.NotEmpty(t, create)

	payload := docutil.EncodeToString(create)

	const alg = "ALG"
	const kid = "kid"
	const signature = "signature"

	t.Run("success", func(t *testing.T) {
		request, err := NewSignedRequest(
			&SignedRequestInfo{Payload: payload, Algorithm: alg, Signature: signature, KID: kid})
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
	t.Run("missing payload", func(t *testing.T) {
		request, err := NewSignedRequest(&SignedRequestInfo{Algorithm: alg, Signature: signature, KID: kid})
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing payload")
	})
	t.Run("missing algorithm", func(t *testing.T) {
		request, err := NewSignedRequest(&SignedRequestInfo{Payload: payload, Signature: signature, KID: kid})
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing algorithm")
	})
	t.Run("missing signing key id", func(t *testing.T) {
		request, err := NewSignedRequest(&SignedRequestInfo{Payload: payload, Algorithm: alg, Signature: signature})
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing signing key ID")
	})
	t.Run("missing signature", func(t *testing.T) {
		request, err := NewSignedRequest(&SignedRequestInfo{Payload: payload, Algorithm: alg, KID: kid})
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing signature")
	})
}

func getTestPatch() (jsonpatch.Patch, error) {
	patchJSON := []byte(`[
		{"op": "replace", "path": "/name", "value": "Jane"}
	]`)

	return jsonpatch.DecodePatch(patchJSON)
}
