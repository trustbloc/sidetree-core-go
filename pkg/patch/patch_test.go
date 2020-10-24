/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patch

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

func TestFromBytes(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patch, err := FromBytes([]byte(addPublicKeysPatch))
		require.NoError(t, err)
		require.NotNil(t, patch)

		action, err := patch.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, AddPublicKeys)

		value, err := patch.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, patch[PublicKeys])

		bytes, err := patch.Bytes()
		require.NoError(t, err)
		require.NotEmpty(t, bytes)

		jsonld := patch.JSONLdObject()
		require.NotNil(t, jsonld)
	})
	t.Run("parse error - invalid character", func(t *testing.T) {
		patch, err := FromBytes([]byte("[test : 123]"))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "invalid character")
	})
	t.Run("parse error - invalid character", func(t *testing.T) {
		patch, err := FromBytes([]byte("[test : 123]"))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "invalid character")
	})
}

func TestActionValidation(t *testing.T) {
	t.Run("error - missing action", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "patch is missing action key")
	})
	t.Run("error -action not supported", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "invalid"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Equal(t, err.Error(), "action 'invalid' is not supported")
	})
	t.Run("error - action type not supported", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": 0}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "action type not supported")
	})
}

func TestPatchesFromDocument(t *testing.T) {
	t.Run("success from new", func(t *testing.T) {
		patches, err := PatchesFromDocument(testDoc)
		require.NoError(t, err)
		require.Equal(t, 3, len(patches))
	})
	t.Run("error - invalid json", func(t *testing.T) {
		p, err := PatchesFromDocument(`invalid`)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "invalid character")
	})
	t.Run("error - document has id", func(t *testing.T) {
		p, err := PatchesFromDocument(`{"id": "abc"}`)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "document must NOT have the id property")
	})
}

func TestReplacePatch(t *testing.T) {
	t.Run("success from bytes", func(t *testing.T) {
		patch, err := FromBytes([]byte(replacePatch))
		require.NoError(t, err)
		require.NotNil(t, patch)

		action, err := patch.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, Replace)

		value, err := patch.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, patch[DocumentKey])
	})
	t.Run("missing document", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "replace"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "replace patch is missing key: document")
	})
	t.Run("success from new", func(t *testing.T) {
		doc, err := document.FromBytes([]byte(replaceDoc))
		require.NoError(t, err)

		p, err := NewReplacePatch(replaceDoc)
		require.NoError(t, err)
		require.NotNil(t, p)

		action, err := p.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, Replace)

		value, err := p.GetValue()
		require.NoError(t, err)
		require.Equal(t, value, doc.JSONLdObject())
	})
	t.Run("error - invalid json", func(t *testing.T) {
		p, err := NewReplacePatch(`invalid`)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "invalid character")
	})
	t.Run("error - document has invalid property", func(t *testing.T) {
		p, err := NewReplacePatch(`{"id": "abc"}`)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "key 'id' is not allowed in replace document")
	})
}

func TestIETFPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patch, err := FromBytes([]byte(ietfPatch))
		require.NoError(t, err)
		require.NotNil(t, patch)

		action, err := patch.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, JSONPatch)

		value, err := patch.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, patch[PatchesKey])
	})
	t.Run("missing patches", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "ietf-json-patch"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "ietf-json-patch patch is missing key: patches")
	})
	t.Run("success from new", func(t *testing.T) {
		p, err := NewJSONPatch(patches)
		require.NoError(t, err)
		require.NotNil(t, p)

		action, err := p.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, JSONPatch)

		value, err := p.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, p[PatchesKey])
	})
}

func TestAddPublicKeysPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patch, err := FromBytes([]byte(addPublicKeysPatch))
		require.NoError(t, err)
		require.NotNil(t, patch)

		action, err := patch.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, AddPublicKeys)

		value, err := patch.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, patch[PublicKeys])
	})
	t.Run("missing public keys", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "add-public-keys"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "add-public-keys patch is missing key: publicKeys")
	})
	t.Run("success from new", func(t *testing.T) {
		p, err := NewAddPublicKeysPatch(testAddPublicKeys)
		require.NoError(t, err)
		require.NotNil(t, p)

		action, err := p.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, AddPublicKeys)

		value, err := p.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, p[PublicKeys])
	})
	t.Run("error - invalid string", func(t *testing.T) {
		p, err := NewAddPublicKeysPatch("invalid-json")
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "public keys invalid: invalid character")
	})
}

func TestRemovePublicKeysPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patch, err := FromBytes([]byte(removePublicKeysPatch))
		require.NoError(t, err)
		require.NotNil(t, patch)

		action, err := patch.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, RemovePublicKeys)

		value, err := patch.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, patch[PublicKeys])
	})
	t.Run("missing public key ids", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "remove-public-keys"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "remove-public-keys patch is missing key: publicKeys")
	})
	t.Run("success from new", func(t *testing.T) {
		const ids = `["key1", "key2"]`
		p, err := NewRemovePublicKeysPatch(ids)
		require.NoError(t, err)
		require.NotNil(t, p)

		action, err := p.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, RemovePublicKeys)

		value, err := p.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, p[PublicKeys])
	})
	t.Run("empty public key ids", func(t *testing.T) {
		const ids = `[]`
		p, err := NewRemovePublicKeysPatch(ids)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "missing public key ids")
	})
	t.Run("error - ids not string array", func(t *testing.T) {
		const ids = `[0, 1]`
		p, err := NewRemovePublicKeysPatch(ids)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "cannot unmarshal")
	})
}

func TestAddServiceEndpointsPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patch, err := FromBytes([]byte(addServiceEndpoints))
		require.NoError(t, err)
		require.NotNil(t, patch)

		action, err := patch.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, AddServiceEndpoints)

		value, err := patch.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, patch[ServiceEndpointsKey])
	})
	t.Run("missing service endpoints", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "add-services"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "add-services patch is missing key: services")
	})
	t.Run("success from new", func(t *testing.T) {
		p, err := NewAddServiceEndpointsPatch(testAddServiceEndpoints)
		require.NoError(t, err)
		require.NotNil(t, p)

		action, err := p.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, AddServiceEndpoints)

		value, err := p.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, p[ServiceEndpointsKey])
	})
	t.Run("error - not json", func(t *testing.T) {
		p, err := NewAddServiceEndpointsPatch("not-json")
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "services invalid: invalid character")
	})
}

func TestRemoveServiceEndpointsPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p, err := FromBytes([]byte(removeServiceEndpoints))
		require.NoError(t, err)
		require.NotNil(t, p)

		action, err := p.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, RemoveServiceEndpoints)

		value, err := p.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, p[ServiceEndpointIdsKey])
	})
	t.Run("missing public key ids", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "remove-services"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "remove-services patch is missing key: ids")
	})
	t.Run("success from new", func(t *testing.T) {
		const ids = `["svc1", "svc2"]`
		p, err := NewRemoveServiceEndpointsPatch(ids)
		require.NoError(t, err)
		require.NotNil(t, p)

		action, err := p.GetAction()
		require.NoError(t, err)
		require.Equal(t, action, RemoveServiceEndpoints)

		value, err := p.GetValue()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, value, p[ServiceEndpointIdsKey])
	})
	t.Run("empty service ids", func(t *testing.T) {
		const ids = `[]`
		p, err := NewRemoveServiceEndpointsPatch(ids)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "missing service ids")
	})
	t.Run("error - ids not string array", func(t *testing.T) {
		const ids = `[0, 1]`
		p, err := NewRemoveServiceEndpointsPatch(ids)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "cannot unmarshal")
	})
}

func TestBytes(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		original, err := FromBytes([]byte(addPublicKeysPatch))
		require.NoError(t, err)
		require.NotNil(t, original)

		bytes, err := original.Bytes()
		require.NoError(t, err)
		require.NotEmpty(t, bytes)

		patch, err := FromBytes(bytes)
		require.NoError(t, err)
		require.Equal(t, original, patch)
	})
	t.Run("error from bytes", func(t *testing.T) {
		patch := Patch{}
		patch["test"] = make(chan int)

		bytes, err := patch.Bytes()
		require.NotNil(t, err)
		require.Nil(t, bytes)
		require.Contains(t, err.Error(), "json: unsupported type: chan int")
	})
}

func TestStringEntry(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		str := stringEntry([]string{"hello"})
		require.Empty(t, str)

		str = stringEntry("hello")
		require.Equal(t, "hello", str)
	})
}

const ietfPatch = `{
  "action": "ietf-json-patch",
  "patches": [{
      "op": "replace",
      "path": "/name",
      "value": "value"
	}]
}`

const patches = `[
	{
      "op": "replace",
      "path": "/some/object/0",
      "value": "value"
	}
]`

const addPublicKeysPatch = `{
	"action": "add-public-keys",
	"publicKeys": [{
		"id": "key1",
		"type": "JsonWebKey2020",
		"purposes": ["verificationMethod"],
		"publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}]
}`

const testAddPublicKeys = `[{
	"id": "key1",
	"type": "JsonWebKey2020",
	"purposes": ["verificationMethod"],
	"publicKeyJwk": {
		"kty": "EC",
		"crv": "P-256K",
		"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
		"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}]`

const removePublicKeysPatch = `{
  "action": "remove-public-keys",
  "publicKeys": ["key1", "key2"]
}`

const addServiceEndpoints = `{
  "action": "add-services",
  "services": [
    {
      "id": "sds1",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://hub.my-personal-server.com"
    },
    {
      "id": "sds2",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://some-cloud.com/hub"
    }
  ]
}`

const testAddServiceEndpoints = `[
    {
      "id": "sds1",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://hub.my-personal-server.com"
    },
    {
      "id": "sds2",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://some-cloud.com/hub"
    }
  ]`

const removeServiceEndpoints = `{
  "action": "remove-services",
  "ids": ["sds1", "sds2"]
}`

const testDoc = `{
	"publicKey": [{
		"id": "key1",
		"type": "JsonWebKey2020",
		"purposes": ["verificationMethod"],
		"publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}],
  	"service": [{
    	"id":"vcs",
    	"type": "VerifiableCredentialService",
    	"serviceEndpoint": "https://example.com/vc/"
  	}],
	"test": "test",
	"other": "value"
}`

const replacePatch = `{
	"action": "replace",
	"document": {
		"publicKeys": [
		{
			"id": "key-1",
			"purposes": ["authentication"],
			"type": "EcdsaSecp256k1VerificationKey2019",
			"publicKeyJwk": {
				"kty": "EC",
				"crv": "P-256K",
				"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
				"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
			}
		}],
		"services": [
		{
			"id": "sds3",
			"type": "SecureDataStore",
			"serviceEndpoint": "http://hub.my-personal-server.com"
		}]
	}
}`

const replaceDoc = `{
	"publicKeys": [
	{
		"id": "key-1",
		"purposes": ["authentication"],
		"type": "EcdsaSecp256k1VerificationKey2019",
		"publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}],
	"services": [
	{
		"id": "sds3",
		"type": "SecureDataStore",
		"serviceEndpoint": "http://hub.my-personal-server.com"
	}]
}`
