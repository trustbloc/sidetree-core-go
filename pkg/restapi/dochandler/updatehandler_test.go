/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

const (
	namespace string = "sample:sidetree:"

	createRequest = `{
  "header": {
    "operation": "create",
    "kid": "#key1",
    "alg": "ES256K"
  },
  "payload": "ewogICJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsCiAgInB1YmxpY0tleSI6IFt7CiAgICAiaWQiOiAiI2tleTEiLAogICAgInR5cGUiOiAiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsCiAgICAicHVibGljS2V5SGV4IjogIjAyZjQ5ODAyZmIzZTA5YzZkZDQzZjE5YWE0MTI5M2QxZTBkYWQwNDRiNjhjZjgxY2Y3MDc5NDk5ZWRmZDBhYTlmMSIKICB9XSwKICAic2VydmljZSI6IFt7CiAgICAiaWQiOiAiSWRlbnRpdHlIdWIiLAogICAgInR5cGUiOiAiSWRlbnRpdHlIdWIiLAogICAgInNlcnZpY2VFbmRwb2ludCI6IHsKICAgICAgIkBjb250ZXh0IjogInNjaGVtYS5pZGVudGl0eS5mb3VuZGF0aW9uL2h1YiIsCiAgICAgICJAdHlwZSI6ICJVc2VyU2VydmljZUVuZHBvaW50IiwKICAgICAgImluc3RhbmNlIjogWyJkaWQ6YmFyOjQ1NiIsICJkaWQ6emF6Ojc4OSJdCiAgICB9CiAgfV0KfQo=",
  "signature": "mAJp4ZHwY5UMA05OEKvoZreRo0XrYe77s3RLyGKArG85IoBULs4cLDBtdpOToCtSZhPvCC2xOUXMGyGXDmmEHg"
}
`
	updateRequest = `{
  "header": {
    "operation": "update",
    "kid": "#key1",
    "alg": "ES256K"
  },
  "payload": "ewogICJkaWRVbmlxdWVTdWZmaXgiOiAiRWlET1FYQzJHbm9WeUh3SVJiamhMeF9jTmM2dm1aYVMwNFNaalpkbExMQVBSZz09IiwKICAib3BlcmF0aW9uTnVtYmVyIjogMSwKICAicHJldmlvdXNPcGVyYXRpb25IYXNoIjogIkVpRE9RWEMyR25vVnlId0lSYmpoTHhfY05jNnZtWmFTMDRTWmpaZGxMTEFQUmc9PSIsCiAgInBhdGNoIjogW3sKICAgICJvcCI6ICJyZW1vdmUiLAogICAgInBhdGgiOiAiL3NlcnZpY2UvMCIKICB9XQp9Cg==",
  "signature": "mAJp4ZHwY5UMA05OEKvoZreRo0XrYe77s3RLyGKArG85IoBULs4cLDBtdpOToCtSZhPvCC2xOUXMGyGXDmmEHg"
}
`
	unsupportedOperationRequest = `{
  "header": {
    "operation": "some operation",
    "kid": "#key1",
    "alg": "ES256K"
  },
  "payload": "ewogICJkaWRVbmlxdWVTdWZmaXgiOiAiRWlET1FYQzJHbm9WeUh3SVJiamhMeF9jTmM2dm1aYVMwNFNaalpkbExMQVBSZz09IiwKICAib3BlcmF0aW9uTnVtYmVyIjogMSwKICAicHJldmlvdXNPcGVyYXRpb25IYXNoIjogIkVpRE9RWEMyR25vVnlId0lSYmpoTHhfY05jNnZtWmFTMDRTWmpaZGxMTEFQUmc9PSIsCiAgInBhdGNoIjogW3sKICAgICJvcCI6ICJyZW1vdmUiLAogICAgInBhdGgiOiAiL3NlcnZpY2UvMCIKICB9XQp9Cg==",
  "signature": "mAJp4ZHwY5UMA05OEKvoZreRo0XrYe77s3RLyGKArG85IoBULs4cLDBtdpOToCtSZhPvCC2xOUXMGyGXDmmEHg"
}
`
	badRequest = `bad request`
)

func TestUpdateHandler_Update(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader([]byte(createRequest)))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
	})
	t.Run("Update", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader([]byte(updateRequest)))
		handler.Update(rw, req)
		require.Equal(t, http.StatusOK, rw.Code)
	})
	t.Run("Unsupported operation", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader([]byte(unsupportedOperationRequest)))
		handler.Update(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})
	t.Run("Bad Request", func(t *testing.T) {
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
		handler := NewUpdateHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader([]byte(badRequest)))
		handler.Update(rw, req)
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})
	t.Run("Error", func(t *testing.T) {
		errExpected := errors.New("create doc error")
		docHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace).WithError(errExpected)
		handler := NewUpdateHandler(docHandler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/document", bytes.NewReader([]byte(createRequest)))
		handler.Update(rw, req)
		require.Equal(t, http.StatusInternalServerError, rw.Code)
		require.Contains(t, rw.Body.String(), errExpected.Error())
	})
}
