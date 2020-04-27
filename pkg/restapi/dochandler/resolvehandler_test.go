/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/request"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
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
			Type:         batch.OperationTypeCreate,
			ID:           id,
			Delta:        delta,
			EncodedDelta: create.Delta,
		})
		require.NoError(t, err)

		getID = func(namespace string, req *http.Request) string { return result.Document.ID() }
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

		create, err := getCreateRequest()
		require.NoError(t, err)

		id, err := docutil.CalculateID(namespace, create.SuffixData, sha2_256)
		require.NoError(t, err)

		initialParam := request.GetInitialStateParam(namespace)
		initialParamValue := create.SuffixData + "." + create.Delta

		initialState := "?" + initialParam + "=" + initialParamValue

		getID = func(namespace string, req *http.Request) string { return id + initialState }
		handler := NewResolveHandler(docHandler)
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
		fmt.Printf("Response: %s\n", rw.Body.String())
		require.Equal(t, "application/did+ld+json", rw.Header().Get("content-type"))
	})
	t.Run("invalid initial state - bad request error", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().
			WithNamespace(namespace)

		id := namespace + docutil.NamespaceDelimiter + "abc"

		initialParam := request.GetInitialStateParam(namespace)

		// pass parameter without value
		initialState := "?" + initialParam + "="

		getID = func(namespace string, req *http.Request) string { return id + initialState }
		handler := NewResolveHandler(docHandler)
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("Invalid ID", func(t *testing.T) {
		getID = func(namespace string, req *http.Request) string { return "someid" }
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewResolveHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})
	t.Run("Not found", func(t *testing.T) {
		getID = func(namespace string, req *http.Request) string {
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
		getID = func(namespace string, req *http.Request) string {
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
			Type:         batch.OperationTypeCreate,
			ID:           id,
			Delta:        delta,
			EncodedDelta: create.Delta,
		})
		require.NoError(t, err)

		_, err = docHandler.ProcessOperation(&batch.Operation{
			Type: batch.OperationTypeDeactivate,
			ID:   result.Document.ID(),
		})
		require.NoError(t, err)

		getID = func(namespace string, req *http.Request) string { return result.Document.ID() }
		handler := NewResolveHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusGone, rw.Code)
	})
}

func TestGetInitialState(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/document", nil)
	initialState := getInitialState(namespace, req)
	require.Empty(t, initialState)

	req = httptest.NewRequest(http.MethodGet, "/document?-sidetree-initial-state=abc", nil)
	initialState = getInitialState(namespace, req)
	require.Equal(t, "?-sidetree-initial-state=abc", initialState)
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

func getDelta() (*model.DeltaModel, error) {
	replace, err := patch.NewReplacePatch(validDoc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          []patch.Patch{replace},
		UpdateCommitment: computeMultihash("updateReveal"),
	}, nil
}

func getSuffixData() *model.SuffixDataModel {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	recoveryKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	return &model.SuffixDataModel{
		DeltaHash:          computeMultihash(validDoc),
		RecoveryKey:        recoveryKey,
		RecoveryCommitment: computeMultihash("recoveryReveal"),
	}
}
