/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"bytes"
	"crypto"
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

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/client"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationapplier"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationparser"
)

const (
	namespace  = "sample:sidetree"
	badRequest = `bad request`

	sha2_256 = 18
)

func TestUpdateHandler_Update(t *testing.T) {
	pc := newMockProtocolClient()
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace).WithProtocolClient(pc)
	handler := NewUpdateHandler(docHandler, pc)

	req, err := getCreateRequestInfo()
	require.NoError(t, err)

	create, err := client.NewCreateRequest(req)
	require.NoError(t, err)

	var createReq model.CreateRequest
	err = json.Unmarshal(create, &createReq)
	require.NoError(t, err)

	uniqueSuffix, err := docutil.CalculateModelMultihash(createReq.SuffixData, sha2_256)
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
		update, err := client.NewUpdateRequest(getUpdateRequestInfo(uniqueSuffix))
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(update))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Deactivate", func(t *testing.T) {
		deactivate, err := client.NewDeactivateRequest(getDeactivateRequestInfo(id))
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(deactivate))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Recover", func(t *testing.T) {
		recover, err := client.NewRecoverRequest(getRecoverRequestInfo(uniqueSuffix))
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
		handler := NewUpdateHandler(docHandlerWithErr, newMockProtocolClient())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader(create))
		handler.Update(rw, req)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), errExpected.Error())
	})
}

func getCreateRequestInfo() (*client.CreateRequestInfo, error) {
	recoveryCommitment, err := commitment.Calculate(testJWK, sha2_256, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.Calculate(testJWK, sha2_256, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &client.CreateRequestInfo{
		OpaqueDocument:     validDoc,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
	}, nil
}

func getUpdateRequestInfo(uniqueSuffix string) *client.UpdateRequestInfo {
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

	updateCommitment, err := commitment.Calculate(testJWK, sha2_256, crypto.SHA256)
	if err != nil {
		panic(err)
	}

	return &client.UpdateRequestInfo{
		DidSuffix:        uniqueSuffix,
		Patches:          []patch.Patch{patchJSON},
		UpdateKey:        pubKey,
		UpdateCommitment: updateCommitment,
		MultihashCode:    sha2_256,
		Signer:           ecsigner.New(privateKey, "ES256", "key-1"),
	}
}

func getDeactivateRequestInfo(uniqueSuffix string) *client.DeactivateRequestInfo {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	return &client.DeactivateRequestInfo{
		DidSuffix:   uniqueSuffix,
		RecoveryKey: testJWK,
		Signer:      ecsigner.New(privateKey, "ES256", ""),
	}
}

func getRecoverRequestInfo(uniqueSuffix string) *client.RecoverRequestInfo {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	recoveryKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	recoveryCommitment, err := commitment.Calculate(testJWK, sha2_256, crypto.SHA256)
	if err != nil {
		panic(err)
	}

	updateCommitment, err := commitment.Calculate(testJWK, sha2_256, crypto.SHA256)
	if err != nil {
		panic(err)
	}

	return &client.RecoverRequestInfo{
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

// operationSchema is used to get operation type.
type operationSchema struct {

	// operation
	Operation operation.Type `json:"type"`
}

const validDoc = `{
	"publicKey": [{
		  "id": "key1",
		  "type": "JsonWebKey2020",
		  "purposes": ["authentication"],
		  "publicKeyJwk": {
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
		"type": "JsonWebKey2020",
		"purposes": ["assertionMethod"],
		"publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
			}
	}]
}`

func newMockProtocolClient() *mocks.MockProtocolClient {
	pc := mocks.NewMockProtocolClient()
	parser := operationparser.New(pc.Protocol)
	dc := doccomposer.New()
	oa := operationapplier.New(pc.Protocol, parser, dc)

	pv := pc.CurrentVersion
	pv.OperationParserReturns(parser)
	pv.OperationApplierReturns(oa)
	pv.DocumentComposerReturns(dc)

	return pc
}
