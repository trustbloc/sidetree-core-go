/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddochandler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationapplier"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationparser"
)

const (
	namespace = "did:sidetree"
	sha2_256  = 18
)

func TestUpdateHandler_Update(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		pc := newMockProtocolClient()
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace).WithProtocolClient(pc)
		handler := NewUpdateHandler(operationsPath, docHandler, pc, &mocks.MetricsProvider{})
		require.Equal(t, operationsPath, handler.Path())
		require.Equal(t, http.MethodPost, handler.Method())
		require.NotNil(t, handler.Handler())

		createRequest, err := getCreateRequest()
		require.NoError(t, err)
		request, err := json.Marshal(createRequest)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, operationsPath, bytes.NewReader(request))
		handler.Handler()(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)

		id, err := getID(createRequest.SuffixData)
		require.NoError(t, err)

		body, err := io.ReadAll(rw.Body)
		require.NoError(t, err)

		var result document.ResolutionResult
		require.NoError(t, json.Unmarshal(body, &result))

		require.Contains(t, result.Document.ID(), id)
	})
}

func TestUpdateHandler_Update_Error(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		pc := newMockProtocolClient()
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace).WithProtocolClient(pc)
		handler := NewUpdateHandler(operationsPath, docHandler, pc, &mocks.MetricsProvider{})

		createRequest, err := getCreateRequest()
		require.NoError(t, err)

		// wrong operation type
		createRequest.Operation = "other"

		request, err := json.Marshal(createRequest)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, operationsPath, bytes.NewReader(request))
		handler.Handler()(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)

		body, err := io.ReadAll(rw.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "bad request: operation type [other] not supported")
	})
}

func getCreateRequest() (*model.CreateRequest, error) {
	delta, err := getDelta()
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData()
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  operation.TypeCreate,
		Delta:      delta,
		SuffixData: suffixData,
	}, nil
}

func getDelta() (*model.DeltaModel, error) {
	patches, err := patch.PatchesFromDocument(validDoc)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.GetCommitment(testJWK, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          patches,
		UpdateCommitment: updateCommitment,
	}, nil
}

func getSuffixData() (*model.SuffixDataModel, error) {
	recoveryCommitment, err := commitment.GetCommitment(testJWK, sha2_256)
	if err != nil {
		return nil, err
	}

	delta, err := getDelta()
	if err != nil {
		return nil, err
	}

	deltaHash, err := hashing.CalculateModelMultihash(delta, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.SuffixDataModel{
		DeltaHash:          deltaHash,
		RecoveryCommitment: recoveryCommitment,
	}, nil
}

func getID(suffixData *model.SuffixDataModel) (string, error) {
	return docutil.CalculateID(namespace, suffixData, sha2_256)
}

const validDoc = `{
	"publicKey": [{
		  "id": "key1",
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

var testJWK = &jws.JWK{
	Kty: "kty",
	Crv: "crv",
	X:   "x",
}

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
