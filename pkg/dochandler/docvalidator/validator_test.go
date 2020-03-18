/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docvalidator

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestNew(t *testing.T) {
	v := New(mocks.NewMockOperationStore(nil))
	require.NotNil(t, v)
}

func TestIsValidOriginalDocument(t *testing.T) {
	v := getDefaultValidator()

	err := v.IsValidOriginalDocument(validDoc)
	require.Nil(t, err)
}

func TestValidatoIsValidOriginalDocumentError(t *testing.T) {
	v := getDefaultValidator()

	err := v.IsValidOriginalDocument(invalidDoc)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "document must NOT have the id property")
}

func TestValidatorIsValidPayload(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	v := New(store)

	store.Put(&batch.Operation{UniqueSuffix: "abc"})

	err := v.IsValidPayload(validUpdate)
	require.Nil(t, err)
}

func TestInvalidPayloadError(t *testing.T) {
	v := getDefaultValidator()

	// payload is invalid json
	payload := []byte("[test : 123]")

	err := v.IsValidPayload(payload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid character")

	err = v.IsValidOriginalDocument(payload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid character")
}

func TestValidatorIsValidPayloadError(t *testing.T) {
	v := getDefaultValidator()

	err := v.IsValidPayload(invalidUpdate)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "missing unique suffix")
}

func TestIsValidPayload_StoreErrors(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	v := New(store)

	// scenario: document is not in the store
	err := v.IsValidPayload(validUpdate)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not found")

	// scenario: found in the store and is valid
	store.Put(&batch.Operation{UniqueSuffix: "abc"})
	err = v.IsValidPayload(validUpdate)
	require.Nil(t, err)

	// scenario: store error
	storeErr := fmt.Errorf("store error")
	v = New(mocks.NewMockOperationStore(storeErr))
	err = v.IsValidPayload(validUpdate)
	require.NotNil(t, err)
	require.Equal(t, err, storeErr)
}

func TestTransofrmDocument(t *testing.T) {
	doc, err := document.FromBytes(validDoc)
	require.NoError(t, err)

	v := getDefaultValidator()

	// there is no transformation for generic doc for now
	transformed, err := v.TransformDocument(doc)
	require.NoError(t, err)
	require.Equal(t, doc, transformed)
}

func getDefaultValidator() *Validator {
	return New(mocks.NewMockOperationStore(nil))
}

var validDoc = []byte(`{ "name": "John Smith" }`)
var invalidDoc = []byte(`{ "id" : "001", "name": "John Smith" }`)

var validUpdate = []byte(`{ "didUniqueSuffix": "abc" }`)
var invalidUpdate = []byte(`{ "patch": "" }`)
