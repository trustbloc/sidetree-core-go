/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didvalidator

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	v := New()
	require.NotNil(t, v)
}

func TestIsValidOriginalDocument(t *testing.T) {
	r := reader(t, "testdata/doc.json")
	didDoc, err := io.ReadAll(r)
	require.Nil(t, err)

	v := New()

	err = v.IsValidOriginalDocument(didDoc)
	require.Nil(t, err)
}

func TestIsValidOriginalDocument_ContextProvidedError(t *testing.T) {
	v := New()

	err := v.IsValidOriginalDocument(docWithContext)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "document must NOT have context")
}

func TestIsValidOriginalDocument_MustNotHaveIDError(t *testing.T) {
	v := New()

	err := v.IsValidOriginalDocument(docWithID)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "document must NOT have the id property")
}

func TestIsValidPayload(t *testing.T) {
	v := New()

	err := v.IsValidPayload(validUpdate)
	require.Nil(t, err)
}

func TestIsValidPayloadError(t *testing.T) {
	v := New()

	err := v.IsValidPayload(invalidUpdate)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "missing did unique suffix")
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
