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

	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
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
		require.Equal(t, basePath+"/operations", handler.Path())
		require.Equal(t, http.MethodPost, handler.Method())
		require.NotNil(t, handler.Handler())

		createRequest, err := getCreateRequest()
		require.NoError(t, err)
		request, err := json.Marshal(createRequest)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document/operations", bytes.NewReader(request))
		handler.Handler()(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)

		id, err := getID(createRequest.SuffixData)
		require.NoError(t, err)

		body, err := ioutil.ReadAll(rw.Body)
		require.NoError(t, err)

		var result document.ResolutionResult
		err = json.Unmarshal(body, &result)

		require.Contains(t, result.Document.ID(), id)
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
		req := httptest.NewRequest(http.MethodPost, "/document/operations", bytes.NewReader(request))
		handler.Handler()(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)

		body, err := ioutil.ReadAll(rw.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "not implemented")
	})
}

func getCreateRequest() (*model.CreateRequest, error) {
	delta, err := getDelta()
	if err != nil {
		return nil, err
	}

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData()
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := canonicalizer.MarshalCanonical(suffixData)
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		Delta:      docutil.EncodeToString(deltaBytes),
		SuffixData: docutil.EncodeToString(suffixDataBytes),
	}, nil
}

func getDelta() (*model.DeltaModel, error) {
	patches, err := patch.PatchesFromDocument(validDoc)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.Calculate(testJWK, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          patches,
		UpdateCommitment: updateCommitment,
	}, nil
}

func getSuffixData() (*model.SuffixDataModel, error) {
	recoveryCommitment, err := commitment.Calculate(testJWK, sha2_256)
	if err != nil {
		return nil, err
	}

	delta, err := getDelta()
	if err != nil {
		return nil, err
	}

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	return &model.SuffixDataModel{
		DeltaHash:          computeMultihash(deltaBytes),
		RecoveryCommitment: recoveryCommitment,
	}, nil
}

func computeMultihash(data []byte) string {
	mh, err := docutil.ComputeMultihash(sha2_256, data)
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

func getID(suffixData string) (string, error) {
	return docutil.CalculateID(namespace, suffixData, sha2_256)
}

const validDoc = `{
	"publicKey": [{
		  "id": "key1",
		  "type": "JsonWebKey2020",
		  "purpose": ["ops", "general"],
		  "jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`

var testJWK = &jws.JWK{
	Kty: "kty",
	Crv: "crv",
	X:   "x",
}
