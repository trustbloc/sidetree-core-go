/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func TestResolveHandler_Resolve(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().
			WithNamespace(namespace)

		create, err := getCreateRequest()
		require.NoError(t, err)

		id, err := docutil.CalculateID(namespace, create.SuffixData, sha2_256)
		require.NoError(t, err)

		delta, err := getDelta()
		require.NoError(t, err)

		result, err := docHandler.ProcessOperation(&batch.Operation{
			Type:       batch.OperationTypeCreate,
			ID:         id,
			DeltaModel: delta,
			Delta:      create.Delta,
		}, 0)
		require.NoError(t, err)

		getID = func(req *http.Request) string { return result.Document.ID() }
		handler := NewResolveHandler(docHandler)
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		fmt.Printf("Response: %s\n", rw.Body.String())
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Success with initial value", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().
			WithNamespace(namespace)

		create, err := getCreateRequestJCS()
		require.NoError(t, err)

		id, err := docutil.CalculateJCSID(namespace, create.SuffixData, sha2_256)
		require.NoError(t, err)

		initialStateJCS, err := canonicalizeThenEncode(create)
		require.NoError(t, err)

		initialState := ":" + initialStateJCS

		getID = func(req *http.Request) string { return id + initialState }
		handler := NewResolveHandler(docHandler)
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		fmt.Printf("Response: %s\n", rw.Body.String())
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})

	t.Run("Invalid ID", func(t *testing.T) {
		getID = func(req *http.Request) string { return "someid" }
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewResolveHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})
	t.Run("Not found", func(t *testing.T) {
		getID = func(req *http.Request) string {
			return namespace + docutil.NamespaceDelimiter + "someid"
		}
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewResolveHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusNotFound, rw.Code)
	})
	t.Run("Error", func(t *testing.T) {
		getID = func(req *http.Request) string {
			return namespace + docutil.NamespaceDelimiter + "someid"
		}
		errExpected := errors.New("get doc error")
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace).WithError(errExpected)
		handler := NewResolveHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), errExpected.Error())
	})
	t.Run("Document is no longer available", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)

		create, err := getCreateRequest()
		require.NoError(t, err)

		id, err := docutil.CalculateID(namespace, create.SuffixData, sha2_256)
		require.NoError(t, err)

		delta, err := getDelta()
		require.NoError(t, err)

		result, err := docHandler.ProcessOperation(&batch.Operation{
			Type:       batch.OperationTypeCreate,
			ID:         id,
			DeltaModel: delta,
			Delta:      create.Delta,
		}, 0)
		require.NoError(t, err)

		_, err = docHandler.ProcessOperation(&batch.Operation{
			Type: batch.OperationTypeDeactivate,
			ID:   result.Document.ID(),
		}, 0)
		require.NoError(t, err)

		getID = func(req *http.Request) string { return result.Document.ID() }
		handler := NewResolveHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusGone, rw.Code)
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

	suffixDataBytes, err := canonicalizer.MarshalCanonical(getSuffixData())
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		Delta:      docutil.EncodeToString(deltaBytes),
		SuffixData: docutil.EncodeToString(suffixDataBytes),
	}, nil
}

func getCreateRequestJCS() (*model.CreateRequestJCS, error) {
	delta, err := getDelta()
	if err != nil {
		return nil, err
	}

	return &model.CreateRequestJCS{
		Operation:  model.OperationTypeCreate,
		Delta:      delta,
		SuffixData: getSuffixData(),
	}, nil
}

func canonicalizeThenEncode(value interface{}) (string, error) {
	jcsBytes, err := canonicalizer.MarshalCanonical(value)
	if err != nil {
		return "", err
	}

	return docutil.EncodeToString(jcsBytes), nil
}

func getDelta() (*model.DeltaModel, error) {
	patches, err := patch.PatchesFromDocument(validDoc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          patches,
		UpdateCommitment: computeMultihash("updateReveal"),
	}, nil
}

func getSuffixData() *model.SuffixDataModel {
	return &model.SuffixDataModel{
		DeltaHash:          computeMultihash(validDoc),
		RecoveryCommitment: computeMultihash("recoveryReveal"),
	}
}

var testJWK = &jws.JWK{
	Kty: "kty",
	Crv: "P-256",
	X:   "x",
}
