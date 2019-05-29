/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"encoding/base64"
	"testing"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"

	"github.com/stretchr/testify/require"
)

func TestGetHash(t *testing.T) {

	hash, err := GetHash(100)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "algorithm not supported")
	require.Nil(t, hash)

	hash, err = GetHash(sha2_256)
	require.Nil(t, err)
	require.NotNil(t, hash)

}

func TestComputeHash(t *testing.T) {

	hash, err := ComputeMultihash(sha2_256, []byte(""))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "empty bytes")
	require.Nil(t, hash)

	hash, err = ComputeMultihash(100, []byte("Test"))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "algorithm not supported")
	require.Nil(t, hash)

	hash, err = ComputeMultihash(sha2_256, []byte("Test"))
	require.Nil(t, err)
	require.NotNil(t, hash)
}

func TestGetOperationHash(t *testing.T) {

	createOp := batch.Operation{
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 "abc",
		Type:                         batch.OperationTypeCreate,
		EncodedPayload:               "encoded",
	}

	hash, err := GetOperationHash(createOp)
	require.Nil(t, err)
	require.NotNil(t, hash)

	// set up invalid multihash code to cause error
	createOp.HashAlgorithmInMultiHashCode = 999
	hash, err = GetOperationHash(createOp)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "algorithm not supported")
	require.Empty(t, hash)
}

func TestIsSupportedMultihash(t *testing.T) {

	// scenario: not base64 encoded (corrupted input)
	supported := IsSupportedMultihash("XXXXXaGVsbG8=")
	require.False(t, supported)

	// scenario: base64 encoded, however not multihash
	supported = IsSupportedMultihash(base64.URLEncoding.EncodeToString([]byte("test")))
	require.False(t, supported)

	// scenario: valid encoded multihash
	hash, err := ComputeMultihash(sha2_256, []byte("test"))
	require.Nil(t, err)
	require.NotNil(t, hash)

	key := base64.URLEncoding.EncodeToString(hash)
	supported = IsSupportedMultihash(key)
	require.True(t, supported)
}
