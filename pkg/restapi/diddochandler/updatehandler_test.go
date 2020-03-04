/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddochandler

import (
	"bytes"
	"encoding/json"
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
	namespace string = "did:sidetree"
	sha2_256         = 18
)

func TestUpdateHandler_Update(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(basePath, docHandler)
		require.Equal(t, basePath, handler.Path())
		require.Equal(t, http.MethodPost, handler.Method())
		require.NotNil(t, handler.Handler())

		encodedPayload, err := getCreatePayload()
		require.NoError(t, err)
		createReq, err := getCreateRequest(encodedPayload)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(createReq))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)

		id, err := getID(encodedPayload)
		require.NoError(t, err)

		body, err := ioutil.ReadAll(rw.Body)
		require.NoError(t, err)

		doc, err := document.DidDocumentFromBytes(body)
		require.Contains(t, doc.ID(), id)
	})
}

func TestUpdateHandler_Update_Error(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(basePath, docHandler)

		encodedPayload, err := getCreatePayload()
		require.NoError(t, err)

		// missing protected header
		createReq := model.Request{
			Payload:   encodedPayload,
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
}

func getCreatePayload() (string, error) {
	schema := &model.CreatePayloadSchema{
		Operation: model.OperationTypeCreate,
		OperationData: model.OperationData{
			Document:          validDoc,
			NextUpdateOTPHash: computeMultihash("updateOTP"),
		},
		SuffixData: model.SuffixDataSchema{
			OperationDataHash:   computeMultihash(validDoc),
			RecoveryKey:         model.PublicKey{PublicKeyHex: "HEX"},
			NextRecoveryOTPHash: computeMultihash("recoverOTP"),
		},
	}

	payload, err := json.Marshal(schema)
	if err != nil {
		return "", err
	}

	return docutil.EncodeToString(payload), nil
}

func computeMultihash(data string) string {
	mh, err := docutil.ComputeMultihash(sha2_256, []byte(data))
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

func getCreateRequest(encodedPayload string) ([]byte, error) {
	req := model.Request{
		Protected: &model.Header{
			Alg: "ES256K",
			Kid: "#key1",
		},
		Payload:   encodedPayload,
		Signature: "",
	}

	return json.Marshal(req)
}

func getID(encodedPayload string) (string, error) {
	return docutil.CalculateID(namespace, encodedPayload, sha2_256)
}

const validDoc = `{
	"created": "2019-09-23T14:16:59.261024-04:00",
	"publicKey": [{
		"controller": "id",
		"id": "did:method:abc#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type": "Ed25519VerificationKey2018"
	}],
	"updated": "2019-09-23T14:16:59.261024-04:00"
}`
