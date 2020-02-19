/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestHandlePayload(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		operation := getOperation(create)
		op, err := handler.handlePayload(operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("update", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		operation := getOperation(update)
		op, err := handler.handlePayload(operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("delete", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		operation := getOperation(delete)
		op, err := handler.handlePayload(operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("unsupported operation type error", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		operation := getOperation(unsupported)
		op, err := handler.handlePayload(operation)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
		require.Nil(t, op)
	})
	t.Run("decode payload error", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		operation := getOperation(create)
		operation.EncodedPayload = "invalid"
		op, err := handler.handlePayload(operation)
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
		require.Nil(t, op)
	})
	t.Run("compute unique suffix (multihash) error", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		operation := getOperation(create)
		operation.HashAlgorithmInMultiHashCode = 1000
		op, err := handler.handlePayload(operation)
		require.Error(t, err)
		require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")
		require.Nil(t, op)
	})
	t.Run("unmarshal payload error", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		validOps := []string{create, update, delete}
		for _, op := range validOps {
			operation := getOperation(op)
			operation.EncodedPayload = base64.URLEncoding.EncodeToString([]byte("not json"))

			op, err := handler.handlePayload(operation)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid character")
			require.Nil(t, op)
		}
	})
}

func getOperation(opType string) *batch.Operation {
	var encodedPayload string

	switch opType {
	case create:
		encodedPayload = getCreatePayload(getEncodedDocument())
	case update:
		encodedPayload = getUpdatePayload()
	case delete:
		encodedPayload = getDeletePayload()
	case unsupported:
		encodedPayload = getUnsupportedPayload()
	}

	// populate common values
	operation := &batch.Operation{
		EncodedPayload:               encodedPayload,
		Signature:                    "",
		SigningKeyID:                 "#key-1",
		HashAlgorithmInMultiHashCode: sha2_256,
	}

	return operation
}
