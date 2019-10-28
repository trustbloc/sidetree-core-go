/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestResolveHandler_Resolve(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().
			WithNamespace(namespace)
		doc, err := docHandler.ProcessOperation(batch.Operation{
			Type:           batch.OperationTypeCreate,
			EncodedPayload: base64.URLEncoding.EncodeToString([]byte(createRequest)),
		})
		require.NoError(t, err)

		getID = func(req *http.Request) string { return doc.ID() }
		handler := NewResolveHandler(docHandler)
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
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
		getID = func(req *http.Request) string { return namespace + "someid" }
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewResolveHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusNotFound, rw.Code)
	})
	t.Run("Error", func(t *testing.T) {
		getID = func(req *http.Request) string { return namespace + "someid" }
		errExpected := errors.New("get doc error")
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace).WithError(errExpected)
		handler := NewResolveHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), errExpected.Error())
	})
}
