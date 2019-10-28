/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHTTPError(t *testing.T) {
	errExpected := errors.New("expected error")
	err := NewHTTPError(http.StatusBadRequest, errExpected)
	require.NotNil(t, err)
	require.Equal(t, http.StatusBadRequest, err.Status())
	require.Equal(t, errExpected.Error(), err.Error())
}
