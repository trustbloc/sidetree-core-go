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
	t.Run("invalid id - too long", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(idLong))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key: id exceeds maximum length")
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

func TestValidateServices(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDoc))
		require.NoError(t, err)

		err = ValidateServices(doc.Services())
		require.Nil(t, err)
	})
	t.Run("success - service can have extra property", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDocExtraProperty))
		require.NoError(t, err)

		err = ValidateServices(doc.Services())
		require.NoError(t, err)
	})
	t.Run("error - missing service id", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDocNoID))
		require.NoError(t, err)

		err = ValidateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service id is missing")
	})

	t.Run("error - missing service type", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDocNoType))
		require.NoError(t, err)

		err = ValidateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service type is missing")
	})
	t.Run("error - missing service endpoint", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDocNoServiceEndpoint))
		require.NoError(t, err)

		err = ValidateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service endpoint is missing")
	})
	t.Run("error - service id too long", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDocLongID))
		require.NoError(t, err)

		err = ValidateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service: id exceeds maximum length")
	})
	t.Run("error - service type too long", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDocLongType))
		require.NoError(t, err)

		err = ValidateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service type exceeds maximum length")
	})
	t.Run("error - service endpoint too long", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDocLongServiceEndpoint))
		require.NoError(t, err)

		err = ValidateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service endpoint exceeds maximum length")
	})
	t.Run("error - service endpoint not URI", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDocEndpointNotURI))
		require.NoError(t, err)

		err = ValidateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service endpoint is not valid URI")
	})
}

func TestValidateID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		err := ValidateID("recovered")
		require.NoError(t, err)
	})
	t.Run("error - id not ASCII encoded character", func(t *testing.T) {
		err := ValidateID("a****")
		require.Error(t, err)
		require.Contains(t, err.Error(), "id contains invalid characters")
	})
	t.Run("error - exceeded maximum length", func(t *testing.T) {
		err := ValidateID("1234567890abcdefghijk")
		require.Error(t, err)
		require.Contains(t, err.Error(), "id exceeds maximum length: 20")
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

func TestIsDelegationKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsDelegationKey(pk.Usage())
	require.False(t, ok)

	pk["usage"] = []interface{}{delegation}
	ok = IsDelegationKey(pk.Usage())
	require.True(t, ok)
}

func TestIsInvocationKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsInvocationKey(pk.Usage())
	require.False(t, ok)

	pk["usage"] = []interface{}{invocation}
	ok = IsInvocationKey(pk.Usage())
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

func TestGeneralKeyUsage(t *testing.T) {
	for _, pubKeyType := range allowedKeyTypesGeneral {
		pk := createMockPublicKeyWithTypeUsage(pubKeyType, []interface{}{general})
		err := ValidatePublicKeys([]PublicKey{pk})
		require.NoError(t, err, "valid usage for type")
	}

	pk := createMockPublicKeyWithTypeUsage("invalidUsage", []interface{}{general})
	err := ValidatePublicKeys([]PublicKey{pk})
	require.Error(t, err, "invalid usage for type")
}

func TestInvalidKeyUsage(t *testing.T) {
	pk := createMockPublicKeyWithTypeUsage(jwsVerificationKey2020, []interface{}{"invalidUsage"})
	err := ValidatePublicKeys([]PublicKey{pk})
	require.Error(t, err, "invalid usage")
}

func TestOpsKeyUsage(t *testing.T) {
	testKeyUsage(t, allowedKeyTypesOps, ops)
}

func TestVerificationKeyUsage(t *testing.T) {
	testKeyUsage(t, allowedKeyTypesVerification, assertion)
	testKeyUsage(t, allowedKeyTypesVerification, auth)
	testKeyUsage(t, allowedKeyTypesVerification, delegation)
	testKeyUsage(t, allowedKeyTypesVerification, invocation)
}

func TestAgreementKeyUsage(t *testing.T) {
	testKeyUsage(t, allowedKeyTypesAgreement, agreement)
}

func testKeyUsage(t *testing.T, allowedKeys existenceMap, pubKeyUsage string) {
	for _, pubKeyType := range allowedKeys {
		pk := createMockPublicKeyWithTypeUsage(pubKeyType, []interface{}{general, pubKeyUsage})
		err := ValidatePublicKeys([]PublicKey{pk})
		require.NoError(t, err, "valid usage for type")

		pk = createMockPublicKeyWithTypeUsage(pubKeyType, []interface{}{pubKeyUsage})
		err = ValidatePublicKeys([]PublicKey{pk})
		require.NoError(t, err, "valid usage for type")
	}

	for _, pubKeyType := range allowedKeyTypesGeneral {
		_, ok := allowedKeys[pubKeyType]
		if ok {
			continue
		}

		pk := createMockPublicKeyWithTypeUsage(pubKeyType, []interface{}{general, pubKeyUsage, agreement})
		err := ValidatePublicKeys([]PublicKey{pk})
		require.Error(t, err, "invalid usage for type")

		pk = createMockPublicKeyWithTypeUsage(pubKeyType, []interface{}{general, pubKeyUsage, assertion})
		err = ValidatePublicKeys([]PublicKey{pk})
		require.Error(t, err, "invalid usage for type")

		pk = createMockPublicKeyWithTypeUsage(pubKeyType, []interface{}{general, pubKeyUsage})
		err = ValidatePublicKeys([]PublicKey{pk})
		require.Error(t, err, "invalid usage for type")

		pk = createMockPublicKeyWithTypeUsage(pubKeyType, []interface{}{pubKeyUsage})
		err = ValidatePublicKeys([]PublicKey{pk})
		require.Error(t, err, "invalid usage for type")
	}
}

func createMockPublicKeyWithTypeUsage(pubKeyType string, usage []interface{}) PublicKey {
	pk := map[string]interface{}{
		"id":    "key1",
		"type":  pubKeyType,
		"usage": usage,
		"jwk": map[string]interface{}{
			"kty": "kty",
			"crv": "crv",
			"x":   "x",
			"y":   "y",
		},
	}

	return pk
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
      "usage": ["ops", "general", "auth", "assertion", "agreement", "delegation", "invocation", "other"],
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

const idLong = `{
  "publicKey": [
    {
      "id": "idwihmorethantwentycharacters",
      "type": "JwsVerificationKey2020",
      "usage": ["ops"],
      "jwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }]
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

const serviceDoc = `{
	"service": [{
		"id": "sid-123_ABC",
		"type": "VerifiableCredentialService",
		"serviceEndpoint": "https://example.com/vc/"
	}]
}`

const serviceDocNoID = `{
	"service": [{
		"id": "",
		"type": "VerifiableCredentialService",
		"serviceEndpoint": "https://example.com/vc/"
	}]
}`

const serviceDocLongID = `{
	"service": [{
		"id": "thisissomeidthathasmorethantwentycharacters",
		"type": "VerifiableCredentialService",
		"serviceEndpoint": "https://example.com/vc/"
	}]
}`

const serviceDocLongType = `{
	"service": [{
		"id": "id",
		"type": "VerifiableCredentialServiceVerifiableCredentialServiceVerifiableCredentialService",
		"serviceEndpoint": "https://example.com/vc/"
	}]
}`

const serviceDocLongServiceEndpoint = `{
	"service": [{
		"id": "sid",
		"type": "VerifiableCredentialService",
		"serviceEndpoint": "https://example.com/vc/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}]
}`

const serviceDocEndpointNotURI = `{
	"service": [{
		"id": "vcs",
		"type": "type",
		"serviceEndpoint": "hello"
	}]
}`

const serviceDocNoType = `{
	"service": [{
		"id": "vcs",
		"type": "",
		"serviceEndpoint": "https://example.com/vc/"
	}]
}`

const serviceDocNoServiceEndpoint = `{
	"service": [{
		"id": "vcs",
		"type": "VerifiableCredentialService",
		"serviceEndpoint": ""
	}]
}`

const serviceDocExtraProperty = `{
	"service": [{
		"id": "vcs",
		"test": "value",
		"type": "VerifiableCredentialService",
		"serviceEndpoint": "https://example.com/vc/"
	}]
}`
