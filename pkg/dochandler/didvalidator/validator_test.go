/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didvalidator

import (
	"encoding/json"
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

	err := v.IsValidOriginalDocument(pubKeyNoID)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "public key id is missing")

	err = v.IsValidOriginalDocument(pubKeyWithController)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "controller is not allowed")
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

	// document to be transformed has to have 'id' field
	// this field is added by sidetree protocol for any document
	const testID = "doc:abc:123"
	doc[document.IDProperty] = testID

	v := getDefaultValidator()

	result, err := v.TransformDocument(doc)
	require.NoError(t, err)

	jsonTransformed, err := json.Marshal(result.Document)
	require.NoError(t, err)

	didDoc, err := document.DidDocumentFromBytes(jsonTransformed)
	require.NoError(t, err)
	require.Equal(t, didDoc.PublicKeys()[0].Controller(), didDoc.ID())
	require.Contains(t, didDoc.PublicKeys()[0].ID(), testID)
	require.Contains(t, didDoc.Services()[0].ID(), testID)
	require.Equal(t, didContext, didDoc.Context()[0])

	expectedPublicKeys := []string{"master", "general-only", "dual-auth-general"}
	require.Equal(t, len(expectedPublicKeys), len(didDoc.PublicKeys()))

	expectedAuthenticationKeys := []string{"master", "dual-auth-general", "auth-only"}
	require.Equal(t, len(expectedAuthenticationKeys), len(didDoc.Authentication()))
}

func getDefaultValidator() *Validator {
	return New(mocks.NewMockOperationStore(nil))
}

func reader(t *testing.T, filename string) io.Reader {
	f, err := os.Open(filename)
	require.Nil(t, err)
	return f
}

var docWithContext = []byte(`{ "@context": ["https://w3id.org/did/v1"], 
"publicKey": [{"id": "key1", "type": "JwsVerificationKey2020", "usage": ["general"]}] 
}`)
var pubKeyNoID = []byte(`{ "publicKey": [{"id": "", "type": "JwsVerificationKey2020"}]}`)
var docWithID = []byte(`{ "id" : "001", "name": "John Smith" }`)

var validUpdate = []byte(`{ "didUniqueSuffix": "abc" }`)
var invalidUpdate = []byte(`{ "patch": "" }`)

var pubKeyWithController = []byte(`{
  "publicKey": [
    {
      "id": "keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ]
}`)
