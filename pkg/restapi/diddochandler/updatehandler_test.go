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
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
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

		createRequest, err := getCreateRequest()
		require.NoError(t, err)
		request, err := json.Marshal(createRequest)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(request))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)

		id, err := getID(createRequest.SuffixData)
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

		createRequest, err := getCreateRequest()
		require.NoError(t, err)

		// wrong operation type
		createRequest.Operation = ""

		request, err := json.Marshal(createRequest)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(request))
		handler.Update(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)

		body, err := ioutil.ReadAll(rw.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "not implemented")
	})
}

func getCreateRequest() (*model.CreateRequest, error) {
	patchData, err := getPatchData()
	if err != nil {
		return nil, err
	}

	patchDataBytes, err := docutil.MarshalCanonical(patchData)
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := docutil.MarshalCanonical(getSuffixData())
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		PatchData:  docutil.EncodeToString(patchDataBytes),
		SuffixData: docutil.EncodeToString(suffixDataBytes),
	}, nil
}

func getPatchData() (*model.PatchDataModel, error) {
	replace, err := patch.NewReplacePatch(validDoc)
	if err != nil {
		return nil, err
	}

	return &model.PatchDataModel{
		Patches:                  []patch.Patch{replace},
		NextUpdateCommitmentHash: computeMultihash("updateReveal"),
	}, nil
}

func getSuffixData() *model.SuffixDataModel {
	return &model.SuffixDataModel{
		PatchDataHash:              computeMultihash(validDoc),
		RecoveryKey:                model.PublicKey{PublicKeyHex: "HEX"},
		NextRecoveryCommitmentHash: computeMultihash("recoveryReveal"),
	}
}

func computeMultihash(data string) string {
	mh, err := docutil.ComputeMultihash(sha2_256, []byte(data))
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

func getID(suffixData string) (string, error) {
	return docutil.CalculateID(namespace, suffixData, sha2_256)
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
