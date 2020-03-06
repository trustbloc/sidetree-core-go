/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	namespace = "sample:sidetree"

	create      = "create"
	update      = "update"
	delete      = "delete"
	unsupported = "unsupported"

	badRequest = `bad request`

	sha2_256 = 18
)

func TestUpdateHandler_Update(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewUpdateHandler(docHandler)

	createReq, err := getCreateRequest()
	require.NoError(t, err)

	t.Run("Create", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(createReq))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))

		id, err := docutil.CalculateID(namespace, docutil.EncodeToString(createReq), sha2_256)
		require.NoError(t, err)

		body, err := ioutil.ReadAll(rw.Body)
		require.NoError(t, err)

		doc, err := document.DidDocumentFromBytes(body)
		require.Contains(t, doc.ID(), id)
		require.Equal(t, len(doc.PublicKeys()), 1)
	})
	t.Run("Update", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(getSignedRequest(update)))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Delete", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(getSignedRequest(delete)))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("missing protected header", func(t *testing.T) {
		createReq := model.Request{
			Payload:   docutil.EncodeToString(createReq),
			Signature: "",
		}

		createReqBytes, err := json.Marshal(createReq)
		require.NoError(t, err)
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(createReqBytes))
		handler.Update(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)

		body, err := ioutil.ReadAll(rw.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "missing protected header")
	})
	t.Run("Unsupported operation", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(getSignedRequest(unsupported)))
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
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(createReq))
		handler.Update(rw, req)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), errExpected.Error())
	})
}

func getCreateRequest() ([]byte, error) {
	schema := &model.CreatePayloadSchema{
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

	return json.Marshal(schema)
}

func computeMultihash(data string) string {
	mh, err := docutil.ComputeMultihash(sha2_256, []byte(data))
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

func getUpdatePayload() string {
	schema := &model.UpdatePayloadSchema{
		Operation:         model.OperationTypeUpdate,
		DidUniqueSuffix:   "",
		Patch:             nil,
		UpdateOTP:         "",
		NextUpdateOTPHash: "",
	}

	payload, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}

	return docutil.EncodeToString(payload)
}

func getDeletePayload() string {
	schema := &model.DeletePayloadSchema{
		Operation:       model.OperationTypeDelete,
		DidUniqueSuffix: "",
	}

	payload, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}

	return docutil.EncodeToString(payload)
}

func getUnsupportedPayload() string {
	schema := &payloadSchema{
		Operation: "unsupported",
	}

	payload, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}

	return docutil.EncodeToString(payload)
}

func getSignedRequest(operation string) []byte {
	var encodedPayload string

	switch operation {
	case update:
		encodedPayload = getUpdatePayload()
	case delete:
		encodedPayload = getDeletePayload()
	case unsupported:
		encodedPayload = getUnsupportedPayload()
	}

	req := model.Request{
		Protected: &model.Header{
			Alg: "ES256K",
			Kid: "#key1",
		},
		Payload:   encodedPayload,
		Signature: "",
	}

	bytes, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}

	return bytes
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
