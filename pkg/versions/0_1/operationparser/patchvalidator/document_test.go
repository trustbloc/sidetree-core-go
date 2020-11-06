/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patchvalidator

import (
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

func TestValidatePublicKeys(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		r := reader(t, "testdata/doc.json")

		data, err := ioutil.ReadAll(r)
		require.Nil(t, err)

		doc, err := document.DidDocumentFromBytes(data)
		require.Nil(t, err)

		err = validatePublicKeys(doc.PublicKeys())
		require.Nil(t, err)
	})

	t.Run("success - missing purpose", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(noPurpose))
		require.Nil(t, err)

		err = validatePublicKeys(doc.PublicKeys())
		require.NoError(t, err)
	})
}

func TestValidatePublicKeysErrors(t *testing.T) {
	t.Run("error - empty purpose", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(emptyPurpose))
		require.Nil(t, err)

		err = validatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "if 'purposes' key is specified, it must contain at least one purpose")
	})
	t.Run("invalid purpose", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(wrongPurpose))
		require.Nil(t, err)

		err = validatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid purpose")
	})
	t.Run("purpose exceeds maximum", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(tooMuchPurpose))
		require.Nil(t, err)

		err = validatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key purpose exceeds maximum length")
	})
	t.Run("invalid key type", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(invalidKeyType))
		require.Nil(t, err)

		err = validatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key type")
	})
	t.Run("missing id", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(noID))
		require.Nil(t, err)

		err = validatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "key 'id' is required for public key")
	})
	t.Run("invalid id - too long", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(idLong))
		require.Nil(t, err)

		err = validatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key: id exceeds maximum length")
	})
	t.Run("duplicate id", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(duplicateID))
		require.Nil(t, err)

		err = validatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "duplicate public key id")
	})

	t.Run("unknown property", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(moreProperties))
		require.Nil(t, err)

		err = validatePublicKeys(doc.PublicKeys())
		require.Error(t, err)
		require.Contains(t, err.Error(), "key 'other' is not allowed for public key")
	})
}

func TestValidateServices(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(serviceDoc))
		require.NoError(t, err)

		err = validateServices(doc.Services())
		require.Nil(t, err)
	})
	t.Run("success - service can have allowed optional property", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(serviceDocOptionalProperty))
		require.NoError(t, err)

		err = validateServices(doc.Services())
		require.NoError(t, err)
	})
	t.Run("error - missing service id", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(serviceDocNoID))
		require.NoError(t, err)

		err = validateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service id is missing")
	})
	t.Run("error - missing service type", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(serviceDocNoType))
		require.NoError(t, err)

		err = validateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service type is missing")
	})
	t.Run("error - missing service endpoint", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(serviceDocNoServiceEndpoint))
		require.NoError(t, err)

		err = validateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service endpoint is missing")
	})
	t.Run("error - service id too long", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(serviceDocLongID))
		require.NoError(t, err)

		err = validateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service: id exceeds maximum length")
	})
	t.Run("error - service type too long", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(serviceDocLongType))
		require.NoError(t, err)

		err = validateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service type exceeds maximum length")
	})
	t.Run("error - service endpoint too long", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(serviceDocLongServiceEndpoint))
		require.NoError(t, err)

		err = validateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service endpoint exceeds maximum length")
	})
	t.Run("error - service endpoint not URI", func(t *testing.T) {
		doc, err := document.DidDocumentFromBytes([]byte(serviceDocEndpointNotURI))
		require.NoError(t, err)

		err = validateServices(doc.Services())
		require.Error(t, err)
		require.Contains(t, err.Error(), "service endpoint is not valid URI")
	})
	t.Run("success - didcomm service", func(t *testing.T) {
		doc, err := document.DIDDocumentFromReader(reader(t, "testdata/doc.json"))
		require.NoError(t, err)
		err = validateServices(doc.Services())
		require.NoError(t, err)
	})
}

func TestValidateID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		err := validateID("recovered")
		require.NoError(t, err)
	})
	t.Run("error - id not ASCII encoded character", func(t *testing.T) {
		err := validateID("a****")
		require.Error(t, err)
		require.Contains(t, err.Error(), "id contains invalid characters")
	})
	t.Run("error - exceeded maximum length", func(t *testing.T) {
		err := validateID("1234567890abcdefghijk123456789012345678901234567890")
		require.Error(t, err)
		require.Contains(t, err.Error(), "id exceeds maximum length: 50")
	})
}

func TestValidateJWK(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		jwk := document.JWK{
			"kty": "kty",
			"crv": "crv",
			"x":   "x",
			"y":   "y",
		}

		err := validateJWK(jwk)
		require.NoError(t, err)
	})

	t.Run("missing kty", func(t *testing.T) {
		jwk := document.JWK{
			"kty": "",
			"crv": "crv",
			"x":   "x",
			"y":   "y",
		}

		err := validateJWK(jwk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWK kty is missing")
	})
}

func TestGeneralKeyPurpose(t *testing.T) {
	for _, pubKeyType := range allowedKeyTypesAgreement {
		pk := createMockPublicKeyWithType(pubKeyType)
		err := validatePublicKeys([]document.PublicKey{pk})
		require.NoError(t, err, "valid purpose for type")
	}

	pk := createMockPublicKeyWithTypeAndPurpose("invalid", []interface{}{document.KeyPurposeAuthentication})
	err := validatePublicKeys([]document.PublicKey{pk})
	require.Error(t, err, "invalid purpose for type")
}

func TestInvalidKeyPurpose(t *testing.T) {
	pk := createMockPublicKeyWithTypeAndPurpose(jsonWebKey2020, []interface{}{"invalidpurpose"})
	err := validatePublicKeys([]document.PublicKey{pk})
	require.Error(t, err, "invalid purpose")
}

func TestVerificationKeyPurpose(t *testing.T) {
	testKeyPurpose(t, allowedKeyTypesVerification, document.KeyPurposeAssertionMethod)
	testKeyPurpose(t, allowedKeyTypesVerification, document.KeyPurposeAuthentication)
	testKeyPurpose(t, allowedKeyTypesVerification, document.KeyPurposeCapabilityDelegation)
	testKeyPurpose(t, allowedKeyTypesVerification, document.KeyPurposeCapabilityInvocation)
}

func TestAgreementKeyPurpose(t *testing.T) {
	testKeyPurpose(t, allowedKeyTypesAgreement, document.KeyPurposeKeyAgreement)
}

func reader(t *testing.T, filename string) io.Reader {
	f, err := os.Open(filename)
	require.Nil(t, err)

	return f
}

func testKeyPurpose(t *testing.T, allowedKeys existenceMap, pubKeyPurpose string) {
	for _, pubKeyType := range allowedKeys {
		pk := createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{pubKeyPurpose})
		err := validatePublicKeys([]document.PublicKey{pk})
		require.NoError(t, err, "valid purpose for type")

		pk = createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{pubKeyPurpose})
		err = validatePublicKeys([]document.PublicKey{pk})
		require.NoError(t, err, "valid purpose for type")
	}

	for _, pubKeyType := range allowedKeyTypesGeneral {
		_, ok := allowedKeys[pubKeyType]
		if ok {
			continue
		}

		pk := createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{pubKeyPurpose, document.KeyPurposeKeyAgreement})
		err := validatePublicKeys([]document.PublicKey{pk})
		require.Error(t, err, "invalid purpose for type")

		pk = createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{pubKeyPurpose, document.KeyPurposeAssertionMethod})
		err = validatePublicKeys([]document.PublicKey{pk})
		require.Error(t, err, "invalid purpose for type")

		pk = createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{pubKeyPurpose})
		err = validatePublicKeys([]document.PublicKey{pk})
		require.Error(t, err, "invalid purpose for type")

		pk = createMockPublicKeyWithTypeAndPurpose(pubKeyType, []interface{}{pubKeyPurpose})
		err = validatePublicKeys([]document.PublicKey{pk})
		require.Error(t, err, "invalid purpose for type")
	}
}

func createMockPublicKeyWithTypeAndPurpose(pubKeyType string, purpose []interface{}) document.PublicKey {
	pk := map[string]interface{}{
		"id":       "key1",
		"type":     pubKeyType,
		"purposes": purpose,
		"publicKeyJwk": map[string]interface{}{
			"kty": "kty",
			"crv": "crv",
			"x":   "x",
			"y":   "y",
		},
	}

	return pk
}

func createMockPublicKeyWithType(pubKeyType string) document.PublicKey {
	pk := map[string]interface{}{
		"id":   "key1",
		"type": pubKeyType,
		"publicKeyJwk": map[string]interface{}{
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
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
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
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const emptyPurpose = `{
  "publicKey": [
    {
      "id": "key1",
      "type": "JsonWebKey2020",
      "purposes": [], 
      "publicKeyJwk": {
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
      "type": "JsonWebKey2020",
      "purposes": ["invalid"],
      "publicKeyJwk": {
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
      "type": "JsonWebKey2020",
      "purposes": ["authentication", "assertionMethod", "keyAgreement", "capabilityDelegation", "capabilityInvocation", "other"],
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]
}`

const idLong = `{
  "publicKey": [
    {
      "id": "idwihmorethan50characters123456789012345678901234567890",
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
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
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
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
      "publicKeyJwk": {
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
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    },
    {
      "id": "key1",
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
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
		"id": "thisissomeidthathasmorethan50characters123456789012345678901234567890",
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

const serviceDocOptionalProperty = `{
	"service": [{
		"id": "vcs",
		"routingKeys": "value",
		"type": "VerifiableCredentialService",
		"serviceEndpoint": "https://example.com/vc/"
	}]
}`
