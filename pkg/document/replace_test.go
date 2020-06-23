/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplaceDocumentFromBytes(t *testing.T) {
	doc, err := ReplaceDocumentFromBytes([]byte(replaceDoc))
	require.Nil(t, err)
	require.NotNil(t, doc)
	require.Equal(t, 1, len(doc.PublicKeys()))
	require.Equal(t, 1, len(doc.Services()))

	jsonld := doc.JSONLdObject()
	require.NotNil(t, jsonld)

	new := ReplaceDocumentFromJSONLDObject(jsonld)
	require.Equal(t, doc.PublicKeys()[0], new.PublicKeys()[0])
}

func TestReplaceDocumentFromBytesError(t *testing.T) {
	doc, err := ReplaceDocumentFromBytes([]byte("[test : 123]"))
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "invalid character")
}

const replaceDoc = `{
	"public_keys": [
	{
		"id": "key-1",
		"purpose": ["auth"],
		"type": "EcdsaSecp256k1VerificationKey2019",
		"jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}],
	"service_endpoints": [
	{
		"id": "sds3",
		"type": "SecureDataStore",
		"endpoint": "http://hub.my-personal-server.com"
	}]
}`
