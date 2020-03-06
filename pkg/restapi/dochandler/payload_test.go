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
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
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

func TestParseCreatePayload(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewUpdateHandler(docHandler)

	t.Run("success", func(t *testing.T) {
		payload, err := getCreateRequest()
		require.NoError(t, err)

		schema, err := handler.parseCreatePayload(payload)
		require.NoError(t, err)
		require.Equal(t, schema.Operation, model.OperationTypeCreate)
	})
	t.Run("failed schema validation", func(t *testing.T) {
		schema, err := handler.parseCreatePayload([]byte("{}"))
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "missing opaque document")
	})
}

func TestValidateCreatePayload(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewUpdateHandler(docHandler)

	t.Run("missing recovery key", func(t *testing.T) {
		schema := getCreatePayloadSchema()
		schema.SuffixData.RecoveryKey.PublicKeyHex = ""
		err := handler.validateCreatePayload(schema)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing recovery key")
	})
	t.Run("invalid operation data hash", func(t *testing.T) {
		schema := getCreatePayloadSchema()
		schema.SuffixData.OperationDataHash = ""
		err := handler.validateCreatePayload(schema)
		require.Error(t, err)
		require.Contains(t, err.Error(), "operation data hash is not computed with the latest supported hash algorithm")
	})
	t.Run("invalid next recovery OTP hash", func(t *testing.T) {
		schema := getCreatePayloadSchema()
		schema.SuffixData.NextRecoveryOTPHash = ""
		err := handler.validateCreatePayload(schema)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery OTP hash is not computed with the latest supported hash algorithm")
	})
	t.Run("invalid next update OTP", func(t *testing.T) {
		schema := getCreatePayloadSchema()
		schema.OperationData.NextUpdateOTPHash = ""
		err := handler.validateCreatePayload(schema)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"next update OTP hash is not computed with the latest supported hash algorithm")
	})
	t.Run("missing opaque document", func(t *testing.T) {
		schema := getCreatePayloadSchema()
		schema.OperationData.Document = ""
		err := handler.validateCreatePayload(schema)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing opaque document")
	})
}

func getCreatePayloadSchema() *model.CreatePayloadSchema {
	return &model.CreatePayloadSchema{
		Operation: model.OperationTypeCreate,
		OperationData: model.OperationData{
			Document:          validDoc,
			NextUpdateOTPHash: computeMultihash("updateOTP"),
		},
		SuffixData: model.SuffixDataSchema{
			OperationDataHash:   computeMultihash(validDoc),
			RecoveryKey:         model.PublicKey{PublicKeyHex: "HEX"},
			NextRecoveryOTPHash: computeMultihash("recoveryOTP"),
		},
	}
}

func getOperation(opType string) *batch.Operation {
	var encodedPayload string

	switch opType {
	case create:
		createReq, err := getCreateRequest()
		if err != nil {
			panic(err)
		}
		encodedPayload = docutil.EncodeToString(createReq)
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
