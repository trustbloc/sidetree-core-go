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

const purposeKey = "purpose"

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
	t.Run("missing purpose", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(noPurpose))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing purpose")
	})
	t.Run("invalid purpose", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(wrongPurpose))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid purpose")
	})
	t.Run("purpose exceeds maximum", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(tooMuchPurpose))
		require.Nil(t, err)

		err = ValidatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key purpose exceeds maximum length")
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
	t.Run("success - service can have allowed optional property", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDocOptionalProperty))
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
	t.Run("success - service property not allowed", func(t *testing.T) {
		doc, err := DidDocumentFromBytes([]byte(serviceDocPropertyNotAllowed))
		require.NoError(t, err)

		err = ValidateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "property 'test' is not allowed for service")
	})
	t.Run("success - didcomm service", func(t *testing.T) {
		doc, err := DIDDocumentFromReader(reader(t, "testdata/doc.json"))
		require.NoError(t, err)
		err = ValidateServices(doc.Services())
		require.NoError(t, err)
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

	pk[purposeKey] = []interface{}{ops}
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
	ok := IsAuthenticationKey(pk.Purpose())
	require.False(t, ok)

	pk[purposeKey] = []interface{}{auth}
	ok = IsAuthenticationKey(pk.Purpose())
	require.True(t, ok)
}

func TestIsAssertionKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsAssertionKey(pk.Purpose())
	require.False(t, ok)

	pk[purposeKey] = []interface{}{assertion}
	ok = IsAssertionKey(pk.Purpose())
	require.True(t, ok)
}

func TestIsAgreementKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsAgreementKey(pk.Purpose())
	require.False(t, ok)

	pk[purposeKey] = []interface{}{agreement}
	ok = IsAgreementKey(pk.Purpose())
	require.True(t, ok)
}

func TestIsDelegationKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsDelegationKey(pk.Purpose())
	require.False(t, ok)

	pk[purposeKey] = []interface{}{delegation}
	ok = IsDelegationKey(pk.Purpose())
	require.True(t, ok)
}

func TestIsInvocationKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsInvocationKey(pk.Purpose())
	require.False(t, ok)

	pk[purposeKey] = []interface{}{invocation}
	ok = IsInvocationKey(pk.Purpose())
	require.True(t, ok)
}

func TestIsGeneralKey(t *testing.T) {
	pk := NewPublicKey(map[string]interface{}{})
	ok := IsGeneralKey(pk.Purpose())
	require.False(t, ok)

	pk[purposeKey] = []interface{}{general}
	ok = IsGeneralKey(pk.Purpose())
	require.True(t, ok)
}

func TestGeneralKeyPurpose(t *testing.T) {
	for _, pubKeyType := range allowedKeyTypesGeneral {
		pk := createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{general})
		err := ValidatePublicKeys([]PublicKey{pk})
		require.NoError(t, err, "valid purpose for type")
	}

	pk := createMockPublicKeyWithTypeAndPurpose("invalid", []interface{}{general})
	err := ValidatePublicKeys([]PublicKey{pk})
	require.Error(t, err, "invalid purpose for type")
}

func TestInvalidKeyPurpose(t *testing.T) {
	pk := createMockPublicKeyWithTypeAndPurpose(jsonWebKey2020, []interface{}{"invalidpurpose"})
	err := ValidatePublicKeys([]PublicKey{pk})
	require.Error(t, err, "invalid purpose")
}

func TestOpsKeyPurpose(t *testing.T) {
	testKeyPurpose(t, allowedKeyTypesOps, ops)
}

func TestVerificationKeyPurpose(t *testing.T) {
	testKeyPurpose(t, allowedKeyTypesVerification, assertion)
	testKeyPurpose(t, allowedKeyTypesVerification, auth)
	testKeyPurpose(t, allowedKeyTypesVerification, delegation)
	testKeyPurpose(t, allowedKeyTypesVerification, invocation)
}

func TestAgreementKeyPurpose(t *testing.T) {
	testKeyPurpose(t, allowedKeyTypesAgreement, agreement)
}

func testKeyPurpose(t *testing.T, allowedKeys existenceMap, pubKeyPurpose string) {
	for _, pubKeyType := range allowedKeys {
		pk := createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{general, pubKeyPurpose})
		err := ValidatePublicKeys([]PublicKey{pk})
		require.NoError(t, err, "valid purpose for type")

		pk = createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{pubKeyPurpose})
		err = ValidatePublicKeys([]PublicKey{pk})
		require.NoError(t, err, "valid purpose for type")
	}

	for _, pubKeyType := range allowedKeyTypesGeneral {
		_, ok := allowedKeys[pubKeyType]
		if ok {
			continue
		}

		pk := createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{general, pubKeyPurpose, agreement})
		err := ValidatePublicKeys([]PublicKey{pk})
		require.Error(t, err, "invalid purpose for type")

		pk = createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{general, pubKeyPurpose, assertion})
		err = ValidatePublicKeys([]PublicKey{pk})
		require.Error(t, err, "invalid purpose for type")

		pk = createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{general, pubKeyPurpose})
		err = ValidatePublicKeys([]PublicKey{pk})
		require.Error(t, err, "invalid purpose for type")

		pk = createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{pubKeyPurpose})
		err = ValidatePublicKeys([]PublicKey{pk})
		require.Error(t, err, "invalid purpose for type")
	}
}

func createMockPublicKeyWithTypeAndPurpose(pubKeyType string, purpose []interface{}) PublicKey {
	pk := map[string]interface{}{
		"id":      "key1",
		"type":    pubKeyType,
		"purpose": purpose,
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
      "purpose": ["ops"], 
      "jwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const noPurpose = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "purpose": [], 
      "jwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const wrongPurpose = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "purpose": ["invalid"],
      "jwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const tooMuchPurpose = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "JwsVerificationKey2020",
      "purpose": ["ops", "general", "auth", "assertion", "agreement", "delegation", "invocation", "other"],
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
      "purpose": ["ops"],
      "jwk": {}
    }
  ]
}`

const idLong = `{
  "publicKey": [
    {
      "id": "idwihmorethantwentycharacters",
      "type": "JwsVerificationKey2020",
      "purpose": ["ops"],
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
      "purpose": ["ops"],
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
      "purpose": ["general"],
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
      "purpose": ["ops"],
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
      "purpose": ["ops"],
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
		"endpoint": "https://example.com/vc/"
	}]
}`

const serviceDocNoID = `{
	"service": [{
		"id": "",
		"type": "VerifiableCredentialService",
		"endpoint": "https://example.com/vc/"
	}]
}`

const serviceDocLongID = `{
	"service": [{
		"id": "thisissomeidthathasmorethantwentycharacters",
		"type": "VerifiableCredentialService",
		"endpoint": "https://example.com/vc/"
	}]
}`

const serviceDocLongType = `{
	"service": [{
		"id": "id",
		"type": "VerifiableCredentialServiceVerifiableCredentialServiceVerifiableCredentialService",
		"endpoint": "https://example.com/vc/"
	}]
}`

const serviceDocLongServiceEndpoint = `{
	"service": [{
		"id": "sid",
		"type": "VerifiableCredentialService",
		"endpoint": "https://example.com/vc/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}]
}`

const serviceDocEndpointNotURI = `{
	"service": [{
		"id": "vcs",
		"type": "type",
		"endpoint": "hello"
	}]
}`

const serviceDocNoType = `{
	"service": [{
		"id": "vcs",
		"type": "",
		"endpoint": "https://example.com/vc/"
	}]
}`

const serviceDocNoServiceEndpoint = `{
	"service": [{
		"id": "vcs",
		"type": "VerifiableCredentialService",
		"endpoint": ""
	}]
}`

const serviceDocOptionalProperty = `{
	"service": [{
		"id": "vcs",
		"routingKeys": "value",
		"type": "VerifiableCredentialService",
		"endpoint": "https://example.com/vc/"
	}]
}`

const serviceDocPropertyNotAllowed = `{
	"service": [{
		"id": "vcs",
		"test": "value",
		"type": "VerifiableCredentialService",
		"endpoint": "https://example.com/vc/"
	}]
}`
