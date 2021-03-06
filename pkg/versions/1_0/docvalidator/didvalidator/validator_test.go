/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didvalidator

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestNew(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)

	v := New(store)
	require.NotNil(t, v)
}

func TestIsValidOriginalDocument(t *testing.T) {
	r := reader(t, "testdata/doc.json")
	didDoc, err := ioutil.ReadAll(r)
	require.Nil(t, err)

	v := getDefaultValidator()

	err = v.IsValidOriginalDocument(didDoc)
	require.Nil(t, err)
}

func TestIsValidOriginalDocument_ContextProvidedError(t *testing.T) {
	v := getDefaultValidator()

	err := v.IsValidOriginalDocument(docWithContext)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "document must NOT have context")
}

func TestIsValidOriginalDocument_MustNotHaveIDError(t *testing.T) {
	v := getDefaultValidator()

	err := v.IsValidOriginalDocument(docWithID)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "document must NOT have the id property")
}

func TestIsValidPayload(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	v := New(store)

	store.Put(&operation.AnchoredOperation{UniqueSuffix: "abc"})

	err := v.IsValidPayload(validUpdate)
	require.Nil(t, err)
}

func TestIsValidPayloadError(t *testing.T) {
	v := getDefaultValidator()

	err := v.IsValidPayload(invalidUpdate)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "missing did unique suffix")
}

func TestIsValidPayload_StoreErrors(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	v := New(store)

	// scenario: document is not in the store
	err := v.IsValidPayload(validUpdate)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not found")

	// scenario: found in the store and is valid
	store.Put(&operation.AnchoredOperation{UniqueSuffix: "abc"})
	err = v.IsValidPayload(validUpdate)
	require.Nil(t, err)

	// scenario: store error
	storeErr := fmt.Errorf("store error")
	v = New(mocks.NewMockOperationStore(storeErr))
	err = v.IsValidPayload(validUpdate)
	require.NotNil(t, err)
	require.Equal(t, err, storeErr)
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

func getDefaultValidator() *Validator {
	return New(mocks.NewMockOperationStore(nil))
}

func reader(t *testing.T, filename string) io.Reader {
	f, err := os.Open(filename)
	require.Nil(t, err)

	return f
}

var (
	docWithContext = []byte(`{ 
	"@context": ["https://w3id.org/did/v1"], 
	"publicKey": [{
      	"id": "key-1",
      	"type": "JsonWebKey2020",
		"publicKeyJwk": {
			"kty": "EC",
        	"crv": "P-256K",
        	"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        	"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      	}
    }] 
}`)

	docWithID = []byte(`{ "id" : "001", "name": "John Smith" }`)

	validUpdate   = []byte(`{ "didSuffix": "abc" }`)
	invalidUpdate = []byte(`{ "patch": "" }`)
)
