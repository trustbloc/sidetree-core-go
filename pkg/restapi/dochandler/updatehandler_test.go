/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
)

const (
	namespace  = "sample:sidetree"
	badRequest = `bad request`

	sha2_256 = 18
)

func TestUpdateHandler_Update(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewUpdateHandler(docHandler)

	req, err := getCreateRequestInfo()
	require.NoError(t, err)

	create, err := helper.NewCreateRequest(req)
	require.NoError(t, err)

	var createReq model.CreateRequest
	err = json.Unmarshal(create, &createReq)
	require.NoError(t, err)

	uniqueSuffix, err := docutil.CalculateUniqueSuffix(createReq.SuffixData, sha2_256)
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

		var result document.ResolutionResult
		err = json.Unmarshal(body, &result)
		require.NoError(t, err)

		doc := result.Document
		require.Equal(t, id, doc.ID())
		require.Equal(t, len(doc.PublicKeys()), 1)
	})
	t.Run("Update", func(t *testing.T) {
		update, err := helper.NewUpdateRequest(getUpdateRequestInfo(uniqueSuffix))
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(update))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Deactivate", func(t *testing.T) {
		deactivate, err := helper.NewDeactivateRequest(getDeactivateRequestInfo(id))
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(deactivate))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Recover", func(t *testing.T) {
		recover, err := helper.NewRecoverRequest(getRecoverRequestInfo(uniqueSuffix))
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(recover))
		handler.Update(rw, req)
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

func getCreateRequestInfo() (*helper.CreateRequestInfo, error) {
	recoveryCommitment, err := commitment.Calculate(testJWK, sha2_256)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.Calculate(testJWK, sha2_256)
	if err != nil {
		return nil, err
	}

	return &helper.CreateRequestInfo{
		OpaqueDocument:     validDoc,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
	}, nil
}

func getUpdateRequestInfo(uniqueSuffix string) *helper.UpdateRequestInfo {
	patchJSON, err := patch.NewJSONPatch(`[{"op": "replace", "path": "/name", "value": "value"}]`)
	if err != nil {
		panic(err)
	}

	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	pubKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	updateCommitment, err := commitment.Calculate(testJWK, sha2_256)
	if err != nil {
		panic(err)
	}

	return &helper.UpdateRequestInfo{
		DidSuffix:        uniqueSuffix,
		Patch:            patchJSON,
		UpdateKey:        pubKey,
		UpdateCommitment: updateCommitment,
		MultihashCode:    sha2_256,
		Signer:           ecsigner.New(privateKey, "ES256", "key-1"),
	}
}

func getDeactivateRequestInfo(uniqueSuffix string) *helper.DeactivateRequestInfo {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	return &helper.DeactivateRequestInfo{
		DidSuffix:   uniqueSuffix,
		RecoveryKey: testJWK,
		Signer:      ecsigner.New(privateKey, "ES256", ""),
	}
}

func getRecoverRequestInfo(uniqueSuffix string) *helper.RecoverRequestInfo {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	recoveryKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	recoveryCommitment, err := commitment.Calculate(testJWK, sha2_256)
	if err != nil {
		panic(err)
	}

	updateCommitment, err := commitment.Calculate(testJWK, sha2_256)
	if err != nil {
		panic(err)
	}

	return &helper.RecoverRequestInfo{
		DidSuffix:          uniqueSuffix,
		OpaqueDocument:     recoverDoc,
		RecoveryKey:        recoveryKey,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
		Signer:             ecsigner.New(privateKey, "ES256", ""),
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

// operationSchema is used to get operation type
type operationSchema struct {

	// operation
	Operation model.OperationType `json:"type"`
}

const validDoc = `{
	"publicKey": [{
		  "id": "key1",
		  "type": "JwsVerificationKey2020",
		  "purpose": ["ops", "general"],
		  "jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`

const recoverDoc = `{
	"publicKey": [{
		"id": "recoverKey",
		"type": "JwsVerificationKey2020",
		"purpose": ["ops"],
		"jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
			}
	}]
}`
