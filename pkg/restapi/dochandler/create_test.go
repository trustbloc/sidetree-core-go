/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func TestParseCreateOperation(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewUpdateHandler(docHandler)

	t.Run("success", func(t *testing.T) {
		request, err := getCreateRequestBytes()
		require.NoError(t, err)

		op, err := handler.parseCreateOperation(request)
		require.NoError(t, err)
		require.Equal(t, batch.OperationTypeCreate, op.Type)
	})
	t.Run("parse create request error", func(t *testing.T) {
		schema, err := handler.parseCreateOperation([]byte(""))
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})
	t.Run("parse suffix data error", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		create.SuffixData = "invalid"
		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := handler.parseCreateOperation(request)
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
		require.Nil(t, op)
	})
	t.Run("parse operation data error", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		create.OperationData = "invalid"
		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := handler.parseCreateOperation(request)
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
		require.Nil(t, op)
	})
}

func TestValidateSuffixData(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewUpdateHandler(docHandler)

	t.Run("missing recovery key", func(t *testing.T) {
		suffixData := getSuffixData()
		suffixData.RecoveryKey.PublicKeyHex = ""
		err := handler.validateSuffixData(suffixData)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing recovery key")
	})
	t.Run("invalid operation data hash", func(t *testing.T) {
		suffixData := getSuffixData()
		suffixData.OperationDataHash = ""
		err := handler.validateSuffixData(suffixData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "operation data hash is not computed with the latest supported hash algorithm")
	})
	t.Run("invalid next recovery OTP hash", func(t *testing.T) {
		suffixData := getSuffixData()
		suffixData.NextRecoveryOTPHash = ""
		err := handler.validateSuffixData(suffixData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery OTP hash is not computed with the latest supported hash algorithm")
	})
}

func TestValidateOperationData(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewUpdateHandler(docHandler)

	t.Run("invalid next update OTP", func(t *testing.T) {
		operationData := getOperationData()
		operationData.NextUpdateOTPHash = ""
		err := handler.validateCreateOperationData(operationData)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"next update OTP hash is not computed with the latest supported hash algorithm")
	})
	t.Run("missing opaque document", func(t *testing.T) {
		operationData := getOperationData()
		operationData.Document = ""
		err := handler.validateCreateOperationData(operationData)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing opaque document")
	})
}

func getCreateRequest() (*model.CreateRequest, error) {
	operationDataBytes, err := docutil.MarshalCanonical(getOperationData())
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := docutil.MarshalCanonical(getSuffixData())
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:     model.OperationTypeCreate,
		OperationData: docutil.EncodeToString(operationDataBytes),
		SuffixData:    docutil.EncodeToString(suffixDataBytes),
	}, nil
}

func getCreateRequestBytes() ([]byte, error) {
	req, err := getCreateRequest()
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}

func getOperationData() *model.CreateOperationData {
	return &model.CreateOperationData{
		Document:          validDoc,
		NextUpdateOTPHash: computeMultihash("updateOTP"),
	}
}

func getSuffixData() *model.SuffixDataSchema {
	return &model.SuffixDataSchema{
		OperationDataHash:   computeMultihash(validDoc),
		RecoveryKey:         model.PublicKey{PublicKeyHex: "HEX"},
		NextRecoveryOTPHash: computeMultihash("recoveryOTP"),
	}
}
