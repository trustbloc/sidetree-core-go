/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	namespace   = "sample:sidetree"
	badRequest  = `bad request`
	recoveryOTP = "recoveryOTP"
	updateOTP   = "updateOTP"

	sha2_256 = 18
)

func TestUpdateHandler_Update(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewUpdateHandler(docHandler)

	create, err := helper.NewCreateRequest(getCreateRequestInfo())
	require.NoError(t, err)

	var createReq model.CreateRequest
	err = json.Unmarshal(create, &createReq)
	require.NoError(t, err)

	id, err := docutil.CalculateID(namespace, createReq.SuffixData, sha2_256)
	require.NoError(t, err)

	t.Run("Create", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(create))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))

		body, err := ioutil.ReadAll(rw.Body)
		require.NoError(t, err)

		doc, err := document.DidDocumentFromBytes(body)
		require.Equal(t, id, doc.ID())
		require.Equal(t, len(doc.PublicKeys()), 1)
	})
	t.Run("Update", func(t *testing.T) {
		update, err := helper.NewUpdateRequest(getUpdateRequestInfo(id))
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(update))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Revoke", func(t *testing.T) {
		revoke, err := helper.NewRevokeRequest(getRevokeRequestInfo(id))
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(revoke))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Recover", func(t *testing.T) {
		recover, err := helper.NewRecoverRequest(getRecoverRequestInfo(id))
		require.NoError(t, err)

		fmt.Println(string(recover))

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(recover))
		handler.Update(rw, req)
		fmt.Println(req.Body)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Unsupported operation", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(getUnsupportedRequest()))
		handler.Update(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})
	t.Run("Bad Request", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader([]byte(badRequest)))
		handler.Update(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})
	t.Run("Error", func(t *testing.T) {
		errExpected := errors.New("create doc error")
		docHandlerWithErr := mocks.NewMockDocumentHandler().WithNamespace(namespace).WithError(errExpected)
		handler := NewUpdateHandler(docHandlerWithErr)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(create))
		handler.Update(rw, req)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), errExpected.Error())
	})
}

func TestGetOperation(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewUpdateHandler(docHandler)

	const uniqueSuffix = "whatever"

	t.Run("create", func(t *testing.T) {
		operation, err := getCreateRequestBytes()
		require.NoError(t, err)

		op, err := handler.getOperation(operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("update", func(t *testing.T) {
		info := getUpdateRequestInfo(uniqueSuffix)
		request, err := helper.NewUpdateRequest(info)
		require.NoError(t, err)

		op, err := handler.getOperation(request)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("revoke", func(t *testing.T) {
		info := getRevokeRequestInfo(uniqueSuffix)
		request, err := helper.NewRevokeRequest(info)
		require.NoError(t, err)

		op, err := handler.getOperation(request)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("recover", func(t *testing.T) {
		info := getRecoverRequestInfo(uniqueSuffix)
		request, err := helper.NewRecoverRequest(info)
		require.NoError(t, err)

		op, err := handler.getOperation(request)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("operation parsing error", func(t *testing.T) {
		// set-up invalid hash algorithm in protocol configuration
		protocol := mocks.NewMockProtocolClient()
		protocol.Protocol.HashAlgorithmInMultiHashCode = 55

		docHandlerWithErr := mocks.NewMockDocumentHandler().WithNamespace(namespace).WithProtocolClient(protocol)
		handlerWithErr := NewUpdateHandler(docHandlerWithErr)

		info := getRecoverRequestInfo(uniqueSuffix)
		request, err := helper.NewRecoverRequest(info)
		require.NoError(t, err)

		op, err := handlerWithErr.getOperation(request)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next update OTP hash is not computed with the latest supported hash algorithm")
		require.Nil(t, op)
	})
	t.Run("unsupported operation type error", func(t *testing.T) {
		operation := getUnsupportedRequest()
		op, err := handler.getOperation(operation)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
		require.Nil(t, op)
	})
}

func getCreateRequestInfo() *helper.CreateRequestInfo {
	return &helper.CreateRequestInfo{
		OpaqueDocument:  validDoc,
		RecoveryKey:     "HEX",
		NextRecoveryOTP: docutil.EncodeToString([]byte(recoveryOTP)),
		NextUpdateOTP:   docutil.EncodeToString([]byte(updateOTP)),
		MultihashCode:   sha2_256,
	}
}

func getUpdateRequestInfo(uniqueSuffix string) *helper.UpdateRequestInfo {
	patchJSON := `[{"op": "replace", "path": "/name", "value": "value"}]`

	return &helper.UpdateRequestInfo{
		DidUniqueSuffix: uniqueSuffix,
		Patch:           patchJSON,
		UpdateOTP:       docutil.EncodeToString([]byte(updateOTP)),
		NextUpdateOTP:   docutil.EncodeToString([]byte(updateOTP)),
		MultihashCode:   sha2_256,
	}
}

func getRevokeRequestInfo(uniqueSuffix string) *helper.RevokeRequestInfo {
	return &helper.RevokeRequestInfo{
		DidUniqueSuffix: uniqueSuffix,
		RecoveryOTP:     docutil.EncodeToString([]byte(recoveryOTP)),
	}
}

func getRecoverRequestInfo(uniqueSuffix string) *helper.RecoverRequestInfo {
	return &helper.RecoverRequestInfo{
		DidUniqueSuffix: uniqueSuffix,
		OpaqueDocument:  recoverDoc,
		RecoveryKey:     "HEX",
		RecoveryOTP:     docutil.EncodeToString([]byte(recoveryOTP)),
		NextRecoveryOTP: docutil.EncodeToString([]byte("newRecoveryOTP")),
		NextUpdateOTP:   docutil.EncodeToString([]byte("newUpdateOTP")),
		MultihashCode:   sha2_256,
	}
}

func computeMultihash(data string) string {
	mh, err := docutil.ComputeMultihash(sha2_256, []byte(data))
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
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

func getCreateRequestBytes() ([]byte, error) {
	req, err := getCreateRequest()
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}

const validDoc = `{
	"created": "2019-09-23T14:16:59.261024-04:00",
	"publicKey": [{
		"id": "#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type": "Ed25519VerificationKey2018"
	}],
	"updated": "2019-09-23T14:16:59.261024-04:00"
}`

const recoverDoc = `{
	"publicKey": [{
		"id": "#recoverKey",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type": "recoverKeyType"
	}]
}`
