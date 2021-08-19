/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docvalidator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	v := New()
	require.NotNil(t, v)
}

func TestIsValidOriginalDocument(t *testing.T) {
	v := New()

	err := v.IsValidOriginalDocument(validDoc)
	require.Nil(t, err)
}

func TestValidatoIsValidOriginalDocumentError(t *testing.T) {
	v := New()

	err := v.IsValidOriginalDocument(invalidDoc)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "document must NOT have the id property")
}

func TestValidatorIsValidPayload(t *testing.T) {
	v := New()

	err := v.IsValidPayload(validUpdate)
	require.NoError(t, err)
}

func TestInvalidPayloadError(t *testing.T) {
	v := New()

	// payload is invalid json
	payload := []byte("[test : 123]")

	err := v.IsValidOriginalDocument(payload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid character")
}

func TestValidatorIsValidPayloadError(t *testing.T) {
	v := New()

	err := v.IsValidPayload(invalidUpdate)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "missing unique suffix")
}

var (
	validDoc   = []byte(`{ "name": "John Smith" }`)
	invalidDoc = []byte(`{ "id" : "001", "name": "John Smith" }`)

	validUpdate   = []byte(`{ "didSuffix": "abc" }`)
	invalidUpdate = []byte(`{ "patch": "" }`)
)
