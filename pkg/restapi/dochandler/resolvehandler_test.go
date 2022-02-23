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

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
)

func TestResolveHandler_Resolve(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().
			WithNamespace(namespace)

		create, err := getCreateRequest()
		require.NoError(t, err)

		bytes, err := canonicalizer.MarshalCanonical(create)
		require.NoError(t, err)

		result, err := docHandler.ProcessOperation(bytes, 0)
		require.NoError(t, err)

		getID = func(req *http.Request) string { return result.Document.ID() }
		handler := NewResolveHandler(docHandler, &mocks.MetricsProvider{})
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		fmt.Printf("Response: %s\n", rw.Body.String())
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Success with initial value", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().
			WithNamespace(namespace).WithProtocolClient(newMockProtocolClient())

		create, err := getCreateRequest()
		require.NoError(t, err)

		id, err := docutil.CalculateID(namespace, create.SuffixData, sha2_256)
		require.NoError(t, err)

		initialStateJCS, err := canonicalizeThenEncode(create)
		require.NoError(t, err)

		initialState := ":" + initialStateJCS

		getID = func(req *http.Request) string { return id + initialState }
		handler := NewResolveHandler(docHandler, &mocks.MetricsProvider{})
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		fmt.Printf("Response: %s\n", rw.Body.String())
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("success - with versionId parameter", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().
			WithNamespace(namespace)

		create, err := getCreateRequest()
		require.NoError(t, err)

		bytes, err := canonicalizer.MarshalCanonical(create)
		require.NoError(t, err)

		result, err := docHandler.ProcessOperation(bytes, 0)
		require.NoError(t, err)

		getID = func(req *http.Request) string { return result.Document.ID() }
		handler := NewResolveHandler(docHandler, &mocks.MetricsProvider{})
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document/"+result.Document.ID()+"?versionId=abc", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("Invalid ID", func(t *testing.T) {
		getID = func(req *http.Request) string { return "someid" }
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewResolveHandler(docHandler, &mocks.MetricsProvider{})

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
		handler := NewResolveHandler(docHandler, &mocks.MetricsProvider{})

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
		handler := NewResolveHandler(docHandler, &mocks.MetricsProvider{})

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

		suffix, err := hashing.CalculateModelMultihash(create.SuffixData, sha2_256)
		require.NoError(t, err)

		createBytes, err := canonicalizer.MarshalCanonical(create)
		require.NoError(t, err)

		result, err := docHandler.ProcessOperation(createBytes, 0)
		require.NoError(t, err)

		deactivate := &model.DeactivateRequest{
			Operation: operation.TypeDeactivate,
			DidSuffix: suffix,
		}

		deactivateBytes, err := canonicalizer.MarshalCanonical(deactivate)
		require.NoError(t, err)

		_, err = docHandler.ProcessOperation(deactivateBytes, 0)
		require.NoError(t, err)

		getID = func(req *http.Request) string { return result.Document.ID() }
		handler := NewResolveHandler(docHandler, &mocks.MetricsProvider{})

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
	})
}

func getCreateRequest() (*model.CreateRequest, error) {
	delta, err := getDelta()
	if err != nil {
		return nil, err
	}

	suffixData := getSuffixData()

	return &model.CreateRequest{
		Operation:  operation.TypeCreate,
		Delta:      delta,
		SuffixData: suffixData,
	}, nil
}

func canonicalizeThenEncode(value interface{}) (string, error) {
	jcsBytes, err := canonicalizer.MarshalCanonical(value)
	if err != nil {
		return "", err
	}

	return encoder.EncodeToString(jcsBytes), nil
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

var recoverJWK = &jws.JWK{
	Kty: "kty",
	Crv: "P-256",
	X:   "x",
}

var updateJWK = &jws.JWK{
	Kty: "kty",
	Crv: "crv",
	X:   "x",
	Y:   "y",
}
