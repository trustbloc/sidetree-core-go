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
	r := reader(t, "testdata/pk-doc.json")

	doc, err := DIDDocumentFromReader(r)
	require.Nil(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "", doc.ID())

	publicKeys := doc.PublicKeys()
	require.Equal(t, []PublicKey{
		{
			"id":       "key1",
			"type":     "JsonWebKey2020",
			"purposes": []interface{}{"authentication"},
			"publicKeyJwk": map[string]interface{}{
				"kty": "EC",
				"crv": "P-256K",
				"x":   "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
				"y":   "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc",
			},
		},
	}, publicKeys)

	services := doc.Services()
	require.Equal(t, []Service{
		{
			"id":              "hub",
			"type":            "IdentityHub",
			"serviceEndpoint": "https://example.com/hub/",
			"routingKeys":     "routingKeysValue",
			"recipientKeys":   "recipientKeysValue",
			"priority":        float64(0),
		},
	}, services)

	jsonld := doc.JSONLdObject()
	require.NotNil(t, jsonld)

	require.Empty(t, doc.Context())
	require.Equal(t, "whatever", doc.Authentications()[0])

	require.Equal(t, 1, len(doc.AlsoKnownAs()))
	require.Equal(t, "identityURI", doc.AlsoKnownAs()[0])

	newDoc := DidDocumentFromJSONLDObject(doc.JSONLdObject())
	require.Equal(t, newDoc, doc)
}

func TestValidWithVerificationMethods(t *testing.T) {
	r := reader(t, "testdata/vm-doc.json")

	doc, err := DIDDocumentFromReader(r)
	require.Nil(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "", doc.ID())

	publicKeys := doc.VerificationMethods()
	require.Equal(t, []PublicKey{
		{
			"id":       "key1",
			"type":     "JsonWebKey2020",
			"purposes": []interface{}{"authentication"},
			"publicKeyJwk": map[string]interface{}{
				"kty": "EC",
				"crv": "P-256K",
				"x":   "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
				"y":   "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc",
			},
		},
	}, publicKeys)
}

func TestEmptyDoc(t *testing.T) {
	var bytes = []byte(`{"@context":"https://w3id.org/did/v1"}`) //nolint:gofumpt

	doc, err := DidDocumentFromBytes(bytes)
	require.Nil(t, err)
	require.NotNil(t, doc)

	require.Equal(t, 0, len(doc.PublicKeys()))
	require.Equal(t, 0, len(doc.Services()))
	require.Equal(t, 0, len(doc.Authentications()))
	require.Equal(t, 0, len(doc.AssertionMethods()))
	require.Equal(t, 0, len(doc.AgreementKeys()))
	require.Equal(t, 0, len(doc.DelegationKeys()))
	require.Equal(t, 0, len(doc.InvocationKeys()))
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
