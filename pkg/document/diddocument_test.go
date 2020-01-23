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
	require.Equal(t, "https://w3id.org/did/v1", doc.Context()[0])

	publicKeys := doc.PublicKeys()
	require.Equal(t, []PublicKey{
		{
			"id":   "#key1",
			"type": "Secp256k1VerificationKey2018",
			"publicKeyJwk": map[string]interface{}{
				"kty":                        "EC",
				"kid":                        "key1",
				"crv":                        "P-256K",
				"x":                          "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
				"y":                          "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc",
				"use":                        "verify",
				"defaultEncryptionAlgorithm": "none",
			},
		},
		{
			"id":           "#key2",
			"type":         "RsaVerificationKey2018",
			"publicKeyPem": "-----BEGIN PUBLIC KEY.2.END PUBLIC KEY-----",
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

	str := doc.String()
	require.NotEmpty(t, str)

	bytes := doc.Bytes()
	require.NotEmpty(t, bytes)

	jsonld := doc.JSONLdObject()
	require.NotNil(t, jsonld)
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
}

func TestMissingInfo(t *testing.T) {
	r := reader(t, "testdata/missing-info.json")

	doc, err := DIDDocumentFromReader(r)
	require.Nil(t, err)
	require.NotNil(t, doc)

	publicKeys := doc.PublicKeys()
	require.Equal(t, 0, len(publicKeys))

	services := doc.Services()
	require.Equal(t, 0, len(services))
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
