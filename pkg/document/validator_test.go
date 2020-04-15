/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidatePublicKeys(t *testing.T) {
	r := reader(t, "testdata/doc.json")

	data, err := ioutil.ReadAll(r)
	require.Nil(t, err)

	doc, err := DidDocumentFromBytes(data)
	require.Nil(t, err)

	err = ValidatePublicKeys(doc.PublicKeys())
	require.Nil(t, err)
}

func TestValidatePublicKeysErrors(t *testing.T) {
	t.Run("missing usage", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(noUsage))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing usage")
	})
	t.Run("invalid usage", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(wrongUsage))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid usage")
	})
	t.Run("usage exceeds maximum", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(tooMuchUsage))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key usage exceeds maximum length")
	})
	t.Run("invalid key type", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(invalidKeyType))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key type")
	})
	t.Run("missing id", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(noID))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key id is missing")
	})
	t.Run("missing JWK", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(noJWK))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "operations key has to be in JWK format")
	})
	t.Run("duplicate id", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(duplicateID))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "duplicate public key id")
	})
}

func TestValidateOperationsKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	pk["id"] = "kid"

	err := ValidateOperationsKey(pk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "is not an operations key")

	pk["usage"] = []interface{}{ops}
	err = ValidateOperationsKey(pk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key has to be in JWK format")

	jwk := map[string]interface{}{
		"kty": "kty",
		"crv": "crv",
		"x":   "x",
		"y":   "y",
	}

	pk["publicKeyJwk"] = jwk
	err = ValidateOperationsKey(pk)
	require.NoError(t, err)
}

const noUsage = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "publicKeyJwk": {
        "kty": "EC",
        "kid": "key1",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const wrongUsage = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "usage": ["invalid"],
      "publicKeyJwk": {
        "kty": "EC",
        "kid": "key1",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const tooMuchUsage = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "usage": ["ops", "general", "auth", "other"],
      "publicKeyJwk": {
        "kty": "EC",
        "kid": "key1",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const noJWK = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "usage": ["ops"]
    }
  ]
}`

const noID = `{
  "publicKey": [
    {
      "type": "JwsVerificationKey2020",
      "usage": ["ops"],
      "publicKeyJwk": {
        "kty": "EC",
        "kid": "key1",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const invalidKeyType = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "InvalidKeyType",
      "usage": ["general"],
      "publicKeyJwk": {
        "kty": "EC",
        "kid": "key1",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const duplicateID = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "usage": ["ops"],
      "publicKeyJwk": {
        "kty": "EC",
        "kid": "key1",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    },
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "usage": ["ops"],
      "publicKeyJwk": {
        "kty": "EC",
        "kid": "key1",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`
