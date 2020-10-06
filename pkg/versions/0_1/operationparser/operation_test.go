/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

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
		SignatureAlgorithms:          []string{"alg"},
		KeyAlgorithms:                []string{"crv"},
		Patches:                      []string{"add-public-keys", "remove-public-keys", "add-service-endpoints", "remove-service-endpoints", "ietf-json-patch"},
	}

	parser := New(p)

	t.Run("create", func(t *testing.T) {
		operation, err := getCreateRequestBytes()
		require.NoError(t, err)

		op, err := parser.Parse(namespace, operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("update", func(t *testing.T) {
		operation, err := getUpdateRequestBytes()
		require.NoError(t, err)

		op, err := parser.Parse(namespace, operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("deactivate", func(t *testing.T) {
		operation, err := getDeactivateRequestBytes()
		require.NoError(t, err)

		op, err := parser.Parse(namespace, operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("recover", func(t *testing.T) {
		operation, err := getRecoverRequestBytes()
		require.NoError(t, err)

		op, err := parser.Parse(namespace, operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("operation parsing error", func(t *testing.T) {
		// set-up invalid hash algorithm in protocol configuration
		invalid := protocol.Protocol{
			HashAlgorithmInMultiHashCode: 55,
			Patches:                      []string{"add-public-keys", "remove-public-keys", "add-service-endpoints", "remove-service-endpoints", "ietf-json-patch"},
		}

		operation, err := getRecoverRequestBytes()
		require.NoError(t, err)

		op, err := New(invalid).Parse(namespace, operation)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next update commitment hash is not computed with the required supported hash algorithm")
		require.Nil(t, op)
	})
	t.Run("unsupported operation type error", func(t *testing.T) {
		operation := getUnsupportedRequest()
		op, err := parser.Parse(namespace, operation)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
		require.Nil(t, op)
	})
	t.Run("unmarshal request error - not JSON", func(t *testing.T) {
		op, err := parser.Parse(namespace, []byte("operation"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal operation buffer into operation schema")
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
