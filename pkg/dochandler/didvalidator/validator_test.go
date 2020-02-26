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

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestNew(t *testing.T) {
	v := New(mocks.NewMockOperationStore(nil))
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

func TestIsValidOriginalDocument_PublicKeyErrors(t *testing.T) {
	v := getDefaultValidator()

	err := v.IsValidOriginalDocument(noPublicKeyDoc)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "document must contain at least one public key")

	err = v.IsValidOriginalDocument(pubKeyNotFragmentDoc)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "public key id is either absent or not starting with #")

	err = v.IsValidOriginalDocument(pubKeyWithController)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "controller is not allowed")
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

	store.Put(&batch.Operation{UniqueSuffix: "abc"})

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

func TestTransformDocument(t *testing.T) {
	r := reader(t, "testdata/doc.json")
	docBytes, err := ioutil.ReadAll(r)
	require.NoError(t, err)
	doc, err := document.FromBytes(docBytes)
	require.NoError(t, err)

	v := getDefaultValidator()

	transformed, err := v.TransformDocument(doc)
	require.NoError(t, err)

	didDoc := document.DidDocumentFromJSONLDObject(transformed.JSONLdObject())
	require.Equal(t, didDoc.PublicKeys()[0].Controller(), didDoc.ID())
}

func getDefaultValidator() *Validator {
	return New(mocks.NewMockOperationStore(nil))
}

func reader(t *testing.T, filename string) io.Reader {
	f, err := os.Open(filename)
	require.Nil(t, err)
	return f
}

var noPublicKeyDoc = []byte(`{ "@context": "some context", "name": "John Smith" }`)
var pubKeyNotFragmentDoc = []byte(`{ "@context": "some context", "publicKey": [{"id": "key1", "type": "type"}]}`)
var docWithID = []byte(`{ "@context": "some context", "id" : "001", "name": "John Smith" }`)

var validUpdate = []byte(`{ "didUniqueSuffix": "abc" }`)
var invalidUpdate = []byte(`{ "patch": "" }`)

var pubKeyWithController = []byte(`{
  "publicKey": [
    {
      "id": "#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ]
}`)
