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
		patch, err := FromBytes([]byte(replacePatch))
		require.NoError(t, err)
		require.NotNil(t, patch)
		require.Equal(t, patch.GetAction(), Replace)

		bytes, err := patch.Bytes()
		require.NoError(t, err)
		require.NotEmpty(t, bytes)

		jsonld := patch.JSONLdObject()
		require.NotNil(t, jsonld)
	})
	t.Run("invalid replace patch", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "replace"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "replace patch is missing document")
	})
	t.Run("parse error - invalid character", func(t *testing.T) {
		patch, err := FromBytes([]byte("[test : 123]"))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "invalid character")
	})
}

func TestActionValidation(t *testing.T) {
	t.Run("missing action", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "patch is missing action property")
	})
	t.Run("action not supported", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "invalid"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Equal(t, err.Error(), "action 'invalid' is not supported")
	})
	t.Run("action not supported", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": 0}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "action type not supported")
	})
}

func TestReplacePatch(t *testing.T) {
	t.Run("success from bytes", func(t *testing.T) {
		patch, err := FromBytes([]byte(replacePatch))
		require.NoError(t, err)
		require.NotNil(t, patch)
		require.Equal(t, patch.GetAction(), Replace)
	})
	t.Run("missing document", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "replace"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "replace patch is missing document")
	})
	t.Run("success from new", func(t *testing.T) {
		doc, err := document.FromBytes([]byte(testDoc))
		require.NoError(t, err)

		p, err := NewReplacePatch(testDoc)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), Replace)
		require.Equal(t, p.GetValue(DocumentKey), doc.JSONLdObject())
	})
	t.Run("error - invalid json", func(t *testing.T) {
		p, err := NewReplacePatch(`invalid`)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "invalid character")
	})
	t.Run("error - document has id", func(t *testing.T) {
		p, err := NewReplacePatch(`{"id": "abc"}`)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "document must NOT have the id property")
	})
}

func TestIETFPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patch, err := FromBytes([]byte(ietfPatch))
		require.NoError(t, err)
		require.NotNil(t, patch)
		require.Equal(t, patch.GetAction(), JSONPatch)
	})
	t.Run("missing patches", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "ietf-json-patch"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "ietf-json-patch patch is missing patches")
	})
	t.Run("success from new", func(t *testing.T) {
		p, err := NewJSONPatch(patches)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), JSONPatch)
		require.NotEmpty(t, p.GetValue(PatchesKey))
	})
	t.Run("invalid JSON patch provided", func(t *testing.T) {
		p, err := NewJSONPatch("{}")
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "cannot unmarshal object into Go value of type jsonpatch.Patch")
	})
}

func TestAddPublicKeysPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patch, err := FromBytes([]byte(addPublicKeysPatch))
		require.NoError(t, err)
		require.NotNil(t, patch)
		require.Equal(t, patch.GetAction(), AddPublicKeys)
	})
	t.Run("missing public keys", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "add-public-keys"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "add-public-keys patch is missing public_keys")
	})
	t.Run("success from new", func(t *testing.T) {
		p, err := NewAddPublicKeysPatch(testAddPublicKeys)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), AddPublicKeys)
		require.NotNil(t, p.GetValue(PublicKeys))
	})
}

func TestRemovePublicKeysPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patch, err := FromBytes([]byte(removePublicKeysPatch))
		require.NoError(t, err)
		require.NotNil(t, patch)
		require.Equal(t, patch.GetAction(), RemovePublicKeys)
	})
	t.Run("missing public key ids", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "remove-public-keys"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "remove-public-keys patch is missing public_keys")
	})
	t.Run("success from new", func(t *testing.T) {
		const ids = `["key1", "key2"]`
		p, err := NewRemovePublicKeysPatch(ids)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), RemovePublicKeys)
		require.NotNil(t, p.GetValue(PublicKeys))
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
		require.Equal(t, patch.GetAction(), AddServiceEndpoints)
	})
	t.Run("missing service endpoints", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "add-service-endpoints"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "add-service-endpoints patch is missing service_endpoints")
	})
	t.Run("success from new", func(t *testing.T) {
		p, err := NewAddServiceEndpointsPatch(testAddServiceEndpoints)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), AddServiceEndpoints)
		require.NotEmpty(t, p.GetValue(ServiceEndpointsKey))
	})
}

func TestRemoveServiceEndpointsPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patch, err := FromBytes([]byte(removeServiceEndpoints))
		require.NoError(t, err)
		require.NotNil(t, patch)
		require.Equal(t, patch.GetAction(), RemoveServiceEndpoints)
	})
	t.Run("missing public key ids", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "remove-service-endpoints"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "remove-service-endpoints patch is missing ids")
	})
	t.Run("success from new", func(t *testing.T) {
		const ids = `["svc1", "svc2"]`
		p, err := NewRemoveServiceEndpointsPatch(ids)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), RemoveServiceEndpoints)
		require.NotEmpty(t, p.GetValue(ServiceEndpointIdsKey))
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
		original, err := FromBytes([]byte(replacePatch))
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

func TestGetValue(t *testing.T) {
	patch, err := FromBytes([]byte(replacePatch))
	require.NoError(t, err)
	require.NotNil(t, patch)

	doc, err := document.FromBytes([]byte(testDoc))
	require.NoError(t, err)

	require.Equal(t, doc.JSONLdObject(), patch.GetValue(DocumentKey))
}

func TestStringEntry(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		str := stringEntry([]string{"hello"})
		require.Empty(t, str)

		str = stringEntry("hello")
		require.Equal(t, "hello", str)
	})
}

const replacePatch = `{
	"action": "replace",
	"document": {
		"service": [{
			"id":"vcs",
			"type": "VerifiableCredentialService",
			"serviceEndpoint": "https://example.com/vc/"
		}]
	}
}`

const ietfPatch = `{
  "action": "ietf-json-patch",
  "patches": [{
      "op": "replace",
      "path": "/service",
      "value": "new value"
	}]
}`

const patches = `[
	{
      "op": "replace",
      "path": "/service",
      "value": "new value"
	}
]`

const addPublicKeysPatch = `{
	"action": "add-public-keys",
	"public_keys": [{
		"id": "key1",
		"type": "JwsVerificationKey2020",
		"usage": ["ops", "general"],
		"jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}]
}`

const testAddPublicKeys = `[{
	"id": "key1",
	"type": "JwsVerificationKey2020",
	"usage": ["ops", "general"],
	"jwk": {
		"kty": "EC",
		"crv": "P-256K",
		"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
		"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}]`

const removePublicKeysPatch = `{
  "action": "remove-public-keys",
  "public_keys": ["key1", "key2"]
}`

const addServiceEndpoints = `{
  "action": "add-service-endpoints",
  "service_endpoints": [
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
  "action": "remove-service-endpoints",
  "ids": ["sds1", "sds2"]
}`

const testDoc = `{
  "service": [{
    "id":"vcs",
    "type": "VerifiableCredentialService",
    "serviceEndpoint": "https://example.com/vc/"
  }]
}`
