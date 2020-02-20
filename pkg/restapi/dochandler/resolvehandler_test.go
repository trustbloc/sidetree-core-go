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
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestResolveHandler_Resolve(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().
			WithNamespace(namespace)

		encodedDocument := getEncodedDocument()
		doc, err := docHandler.ProcessOperation(&batch.Operation{
			Type:            batch.OperationTypeCreate,
			EncodedPayload:  getCreatePayload(encodedDocument),
			EncodedDocument: encodedDocument,
		})
		require.NoError(t, err)

		getID = func(req *http.Request) string { return doc.ID() }
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
		getID = func(req *http.Request) string { return namespace + docutil.NamespaceDelimiter + "someid" }
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewResolveHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusNotFound, rw.Code)
	})
	t.Run("Error", func(t *testing.T) {
		getID = func(req *http.Request) string { return namespace + docutil.NamespaceDelimiter + "someid" }
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

		encodedDocument := getEncodedDocument()
		doc, err := docHandler.ProcessOperation(&batch.Operation{
			Type:            batch.OperationTypeCreate,
			EncodedPayload:  getCreatePayload(encodedDocument),
			EncodedDocument: encodedDocument,
		})
		require.NoError(t, err)

		_, err = docHandler.ProcessOperation(&batch.Operation{
			Type: batch.OperationTypeDelete,
			ID:   doc.ID(),
		})
		require.NoError(t, err)

		getID = func(req *http.Request) string { return doc.ID() }
		handler := NewResolveHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/document", nil)
		handler.Resolve(rw, req)
		require.Equal(t, http.StatusGone, rw.Code)
	})
}
