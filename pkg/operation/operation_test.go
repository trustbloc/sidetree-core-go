/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

const namespace = "did:sidetree"

func TestGetOperation(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
	}

	t.Run("create", func(t *testing.T) {
		operation, err := getCreateRequestBytes()
		require.NoError(t, err)

		op, err := ParseOperation(namespace, operation, p)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("update", func(t *testing.T) {
		operation, err := getUpdateRequestBytes()
		require.NoError(t, err)

		op, err := ParseOperation(namespace, operation, p)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("deactivate", func(t *testing.T) {
		operation, err := getDeactivateRequestBytes()
		require.NoError(t, err)

		op, err := ParseOperation(namespace, operation, p)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("recover", func(t *testing.T) {
		operation, err := getRecoverRequestBytes()
		require.NoError(t, err)

		op, err := ParseOperation(namespace, operation, p)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("operation parsing error", func(t *testing.T) {
		// set-up invalid hash algorithm in protocol configuration
		invalid := protocol.Protocol{
			HashAlgorithmInMultiHashCode: 55,
		}

		operation, err := getRecoverRequestBytes()
		require.NoError(t, err)

		op, err := ParseOperation(namespace, operation, invalid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next update commitment hash is not computed with the latest supported hash algorithm")
		require.Nil(t, op)
	})
	t.Run("unsupported operation type error", func(t *testing.T) {
		operation := getUnsupportedRequest()
		op, err := ParseOperation(namespace, operation, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
		require.Nil(t, op)
	})
}

func getUnsupportedRequest() []byte {
	schema := &operationSchema{
		Operation: "unsupported",
	}

	payload, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}

	return payload
}
