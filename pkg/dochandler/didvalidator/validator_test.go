/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didvalidator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
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

func TestIsValidOriginalDocument_ServiceErrors(t *testing.T) {
	v := getDefaultValidator()

	err := v.IsValidOriginalDocument(serviceNoID)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "service id is missing")
}

func TestIsValidOriginalDocument_PublicKeyErrors(t *testing.T) {
	v := getDefaultValidator()

	err := v.IsValidOriginalDocument(pubKeyNoID)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "public key id is missing")

	err = v.IsValidOriginalDocument(pubKeyWithController)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "invalid number of public key properties")
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
	require.Equal(t, didContext, didDoc.Context()[0])

	// validate services
	service := didDoc.Services()[0]
	require.Contains(t, service.ID(), testID)
	require.NotEmpty(t, service.Endpoint())
	require.Equal(t, "recipientKeysValue", service["recipientKeys"])
	require.Equal(t, "routingKeysValue", service["routingKeys"])
	require.Equal(t, "IdentityHub", service.Type())

	// validate public keys
	pk := didDoc.PublicKeys()[0]
	require.Contains(t, pk.ID(), testID)
	require.NotEmpty(t, pk.Type())
	require.Empty(t, pk.JWK())
	require.NotEmpty(t, pk.PublicKeyJwk())
	require.Empty(t, pk.PublicKeyBase58())

	expectedPublicKeys := []string{"master", "general-only", "dual-auth-gen", "dual-assertion-gen",
		"dual-agreement-gen", "dual-delegation-gen", "dual-invocation-gen"}
	require.Equal(t, len(expectedPublicKeys), len(didDoc.PublicKeys()))

	expectedAuthenticationKeys := []string{"master", "dual-auth-gen", "auth-only"}
	require.Equal(t, len(expectedAuthenticationKeys), len(didDoc.Authentication()))

	expectedAssertionMethodKeys := []string{"master", "dual-assertion-gen", "assertion-only"}
	require.Equal(t, len(expectedAssertionMethodKeys), len(didDoc.AssertionMethod()))

	expectedAgreementKeys := []string{"master", "dual-agreement-gen", "agreement-only"}
	require.Equal(t, len(expectedAgreementKeys), len(didDoc.AgreementKey()))

	expectedDelegationKeys := []string{"master", "dual-delegation-gen", "delegation-only"}
	require.Equal(t, len(expectedDelegationKeys), len(didDoc.DelegationKey()))

	expectedInvocationKeys := []string{"master", "dual-invocation-gen", "invocation-only"}
	require.Equal(t, len(expectedInvocationKeys), len(didDoc.InvocationKey()))
}

func TestEd25519VerificationKey2018(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk, err := pubkey.GetPublicKeyJWK(publicKey)
	require.NoError(t, err)

	publicKeyBytes, err := json.Marshal(jwk)
	require.NoError(t, err)

	data := fmt.Sprintf(ed25519DocTemplate, string(publicKeyBytes))
	doc, err := document.FromBytes([]byte(data))
	require.NoError(t, err)

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
	require.Equal(t, didContext, didDoc.Context()[0])

	// validate service
	service := didDoc.Services()[0]
	require.Contains(t, service.ID(), testID)
	require.NotEmpty(t, service.Endpoint())
	require.Equal(t, "OpenIdConnectVersion1.0Service", service.Type())

	// validate public key
	pk := didDoc.PublicKeys()[0]
	require.Contains(t, pk.ID(), testID)
	require.Equal(t, "Ed25519VerificationKey2018", pk.Type())
	require.Empty(t, pk.JWK())
	require.Empty(t, pk.PublicKeyJwk())

	// test base58 encoding
	require.Equal(t, base58.Encode(publicKey), pk.PublicKeyBase58())

	// validate length of expected keys
	expectedPublicKeys := []string{"dual-assertion-general"}
	require.Equal(t, len(expectedPublicKeys), len(didDoc.PublicKeys()))

	expectedAssertionMethodKeys := []string{"dual-assertion-general"}
	require.Equal(t, len(expectedAssertionMethodKeys), len(didDoc.AssertionMethod()))

	require.Equal(t, 0, len(didDoc.Authentication()))
	require.Equal(t, 0, len(didDoc.AgreementKey()))
}

func TestEd25519VerificationKey2018_Error(t *testing.T) {
	doc, err := document.FromBytes([]byte(ed25519Invalid))
	require.NoError(t, err)

	const testID = "doc:abc:123"
	doc[document.IDProperty] = testID

	v := getDefaultValidator()

	result, err := v.TransformDocument(doc)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "unknown curve")
}

func getDefaultValidator() *Validator {
	return New(mocks.NewMockOperationStore(nil))
}

func reader(t *testing.T, filename string) io.Reader {
	f, err := os.Open(filename)
	require.Nil(t, err)
	return f
}

var docWithContext = []byte(`{ 
	"@context": ["https://w3id.org/did/v1"], 
	"publicKey": [{
      	"id": "key-1",
      	"type": "JwsVerificationKey2020",
      	"usage": ["ops", "general"],
		"jwk": {
			"kty": "EC",
        	"crv": "P-256K",
        	"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        	"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      	}
    }] 
}`)

var pubKeyNoID = []byte(`{ "publicKey": [{"id": "", "type": "JwsVerificationKey2020"}]}`)
var serviceNoID = []byte(`{ "service": [{"id": "", "type": "IdentityHub", "serviceEndpoint": "https://example.com/hub"}]}`)
var docWithID = []byte(`{ "id" : "001", "name": "John Smith" }`)

var validUpdate = []byte(`{ "did_suffix": "abc" }`)
var invalidUpdate = []byte(`{ "patch": "" }`)

var pubKeyWithController = []byte(`{
  "publicKey": [{
      "id": "key-1",
      "type": "JwsVerificationKey2020",
      "controller": "did:example:123456789abcdefghi",
      "usage": ["ops", "general"],
      "jwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
	}]
}`)

const ed25519DocTemplate = `{
  "publicKey": [
	{
  		"id": "dual-assertion-general",
  		"type": "Ed25519VerificationKey2018",
		"usage": ["general", "assertion"],
  		"jwk": %s
	}
  ],
  "service": [
	{
	   "id": "oidc",
	   "type": "OpenIdConnectVersion1.0Service",
	   "serviceEndpoint": "https://openid.example.com/"
	}
  ]
}`

const ed25519Invalid = `{
  "publicKey": [
	{
  		"id": "dual-assertion-general",
  		"type": "Ed25519VerificationKey2018",
		"usage": ["general", "assertion"],
      	"jwk": {
        	"kty": "OKP",
        	"crv": "curve",
        	"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        	"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      	}
	}
  ]
}`
