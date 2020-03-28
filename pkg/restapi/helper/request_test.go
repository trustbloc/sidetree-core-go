/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

const (
	didUniqueSuffix = "whatever"
	opaqueDoc       = "doc"
	recoveryKey     = "recoveryKey"

	sha2_256 = 18
)

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

func TestNewUpdateRequest(t *testing.T) {
	const didUniqueSuffix = "whatever"
	patch := getTestPatch()

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

		fmt.Println(string(request))
	})
}

func getTestPatch() string {
	return `[{"op": "replace", "path": "/name", "value": "Jane"}]`
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
		info.RecoveryKey = ""

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
	t.Run("next update otp not encoded", func(t *testing.T) {
		info := getRecoverRequestInfo()
		info.NextUpdateOTP = "otp"

		request, err := NewRecoverRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "illegal base64 data")
	})
	t.Run("next recover otp not encoded", func(t *testing.T) {
		info := getRecoverRequestInfo()
		info.NextRecoveryOTP = "otp"

		request, err := NewRecoverRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "illegal base64 data")
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

func getRecoverRequestInfo() *RecoverRequestInfo {
	return &RecoverRequestInfo{
		DidUniqueSuffix: didUniqueSuffix,
		OpaqueDocument:  opaqueDoc,
		RecoveryKey:     recoveryKey,
		MultihashCode:   sha2_256}
}
