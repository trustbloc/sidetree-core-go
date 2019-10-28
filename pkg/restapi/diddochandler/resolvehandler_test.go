/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddochandler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestResolveHandler_Resolve(t *testing.T) {
	docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	handler := NewResolveHandler(docHandler)
	require.Equal(t, Path+"/{id}", handler.Path())
	require.Equal(t, http.MethodGet, handler.Method())
	require.NotNil(t, handler.Handler())

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/document", nil)
	handler.Resolve(rw, req)
	require.Equal(t, http.StatusBadRequest, rw.Code)
	require.Contains(t, rw.Body.String(), "must start with supported namespace")
}
