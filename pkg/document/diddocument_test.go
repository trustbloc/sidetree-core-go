/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValid(t *testing.T) {
	r := reader(t, "testdata/doc.json")

	doc, err := DIDDocumentFromReader(r)
	require.Nil(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "", doc.ID())

	publicKeys := doc.PublicKeys()
	require.Equal(t, []PublicKey{
		{
			"id":    "key1",
			"type":  "JwsVerificationKey2020",
			"usage": []interface{}{"ops", "general"},
			"publicKeyJwk": map[string]interface{}{
				"kty": "EC",
				"kid": "key1",
				"crv": "P-256K",
				"x":   "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
				"y":   "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc",
			},
		},
	}, publicKeys)

	services := doc.Services()
	require.Equal(t, []Service{
		{
			"id":   "IdentityHub",
			"type": "IdentityHub",
			"serviceEndpoint": map[string]interface{}{
				"@context": "schema.identity.foundation/hub",
				"@type":    "UserServiceEndpoint",
				"instance": []interface{}{"did:sidetree:456", "did:sidetree:789"},
			},
		},
	}, services)

	jsonld := doc.JSONLdObject()
	require.NotNil(t, jsonld)

	require.Empty(t, doc.Context())
	require.Equal(t, "whatever", doc.Authentication()[0])
}

func TestEmptyDoc(t *testing.T) {
	var bytes = []byte(`{ "@context": "https://w3id.org/did/v1" }`)

	doc, err := DidDocumentFromBytes(bytes)
	require.Nil(t, err)
	require.NotNil(t, doc)

	publicKeys := doc.PublicKeys()
	require.Equal(t, 0, len(publicKeys))

	services := doc.Services()
	require.Equal(t, 0, len(services))

	authentication := doc.Authentication()
	require.Equal(t, 0, len(authentication))

	assertionMethod := doc.AssertionMethod()
	require.Equal(t, 0, len(assertionMethod))
}

func TestInvalidLists(t *testing.T) {
	r := reader(t, "testdata/invalid-lists.json")

	doc, err := DIDDocumentFromReader(r)
	require.Nil(t, err)
	require.NotNil(t, doc)

	services := doc.Services()
	require.Equal(t, 0, len(services))

	pubKeys := doc.PublicKeys()
	require.Equal(t, 0, len(pubKeys))
}
