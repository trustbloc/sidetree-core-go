/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func TestWriteResponse(t *testing.T) {
	rw := httptest.NewRecorder()
	WriteResponse(rw, http.StatusOK, "content")
	require.Equal(t, http.StatusOK, rw.Code)
	require.Equal(t, "\"content\"\n", rw.Body.String())
}

func TestWriteError(t *testing.T) {
	rw := httptest.NewRecorder()

	e := errors.New("some error")
	WriteError(rw, http.StatusBadRequest, e)
	require.Equal(t, http.StatusBadRequest, rw.Code)

	errExpected := &model.Error{Message: e.Error()}
	errBytes, err := json.Marshal(errExpected)
	require.NoError(t, err)
	require.Equal(t, string(errBytes)+"\n", rw.Body.String())
}
