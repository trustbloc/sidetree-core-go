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
	t.Run("invalid number of JWK properties", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(noJWK))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid number of JWK properties")
	})
	t.Run("duplicate id", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(duplicateID))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "duplicate public key id")
	})

	t.Run("unknown property", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(moreProperties))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid number of public key properties")
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

	pk["jwk"] = jwk
	err = ValidateOperationsKey(pk)
	require.NoError(t, err)
}

func TestValidateJWK(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		jwk := JWK{
			"kty": "kty",
			"crv": "crv",
			"x":   "x",
			"y":   "y",
		}

		err := ValidateJWK(jwk)
		require.NoError(t, err)
	})
	t.Run("invalid property", func(t *testing.T) {
		jwk := JWK{
			"kty":   "kty",
			"crv":   "crv",
			"x":     "x",
			"y":     "y",
			"other": "value",
		}

		err := ValidateJWK(jwk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid number of JWK properties")
	})

	t.Run("missing kty", func(t *testing.T) {
		jwk := JWK{
			"kty": "",
			"crv": "crv",
			"x":   "x",
			"y":   "y",
		}

		err := ValidateJWK(jwk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWK kty is missing")
	})

	t.Run("missing crv", func(t *testing.T) {
		jwk := JWK{
			"kty": "kty",
			"crv": "",
			"x":   "x",
			"y":   "y",
		}

		err := ValidateJWK(jwk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWK crv is missing")
	})

	t.Run("missing x", func(t *testing.T) {
		jwk := JWK{
			"kty": "kty",
			"crv": "crv",
			"x":   "",
			"y":   "y",
		}

		err := ValidateJWK(jwk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWK x is missing")
	})

	t.Run("missing y", func(t *testing.T) {
		jwk := JWK{
			"kty": "kty",
			"crv": "crv",
			"x":   "x",
			"y":   "",
		}

		err := ValidateJWK(jwk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWK y is missing")
	})
}

func TestIsAuthenticationKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsAuthenticationKey(pk.Usage())
	require.False(t, ok)

	pk["usage"] = []interface{}{auth}
	ok = IsAuthenticationKey(pk.Usage())
	require.True(t, ok)
}

func TestIsAssertionKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsAssertionKey(pk.Usage())
	require.False(t, ok)

	pk["usage"] = []interface{}{assertion}
	ok = IsAssertionKey(pk.Usage())
	require.True(t, ok)
}

func TestIsAgreementKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsAgreementKey(pk.Usage())
	require.False(t, ok)

	pk["usage"] = []interface{}{agreement}
	ok = IsAgreementKey(pk.Usage())
	require.True(t, ok)
}

func TestIsGeneralKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsGeneralKey(pk.Usage())
	require.False(t, ok)

	pk["usage"] = []interface{}{general}
	ok = IsGeneralKey(pk.Usage())
	require.True(t, ok)
}

const moreProperties = `{
  "publicKey": [
    {
      "id": "key1",
      "other": "unknown",
      "type": "JwsVerificationKey2020",
      "usage": ["ops"], 
      "jwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const noUsage = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "usage": [], 
      "jwk": {
        "kty": "EC",
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
      "jwk": {
        "kty": "EC",
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
      "usage": ["ops", "general", "auth", "assertion", "agreement", "other"],
      "jwk": {
        "kty": "EC",
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
      "usage": ["ops"],
      "jwk": {}
    }
  ]
}`

const noID = `{
  "publicKey": [
    {
      "type": "JwsVerificationKey2020",
      "usage": ["ops"],
      "jwk": {
        "kty": "EC",
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
      "jwk": {
        "kty": "EC",
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
      "jwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    },
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "usage": ["ops"],
      "jwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`
