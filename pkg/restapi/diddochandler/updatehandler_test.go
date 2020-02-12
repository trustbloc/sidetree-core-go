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

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	namespace string = "did:sidetree"
	sha2256          = 18
)

func TestUpdateHandler_Update(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(basePath, docHandler)
		require.Equal(t, basePath, handler.Path())
		require.Equal(t, http.MethodPost, handler.Method())
		require.NotNil(t, handler.Handler())

		encodedPayload, err := getEncodedPayload([]byte(validDoc))
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
		require.Contains(t, string(body), id)
	})
}

func getEncodedPayload(doc []byte) (string, error) {
	payload, err := json.Marshal(
		struct {
			Operation   model.OperationType `json:"type"`
			DIDDocument string              `json:"didDocument"`
		}{model.OperationTypeCreate, docutil.EncodeToString(doc)})

	if err != nil {
		return "", err
	}

	return docutil.EncodeToString(payload), nil
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
	return docutil.CalculateID(namespace, encodedPayload, sha2256)
}

const validDoc = `{
	"@context": ["https://w3id.org/did/v1"],
	"created": "2019-09-23T14:16:59.261024-04:00",
	"publicKey": [{
		"controller": "id",
		"id": "did:method:abc#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type": "Ed25519VerificationKey2018"
	}],
	"updated": "2019-09-23T14:16:59.261024-04:00"
}`
