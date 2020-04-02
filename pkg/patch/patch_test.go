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
	t.Run("action is not string", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": 10}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "action is not string value")
	})
	t.Run("action not supported", func(t *testing.T) {
		patch, err := FromBytes([]byte(`{"action": "invalid"}`))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Equal(t, err.Error(), "action 'invalid' is not supported")
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
		p, err := NewReplacePatch(testDoc)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), Replace)
		require.Equal(t, p.GetStringValue(DocumentKey), testDoc)
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
		require.Equal(t, p.GetStringValue(PatchesKey), patches)
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
		require.Contains(t, err.Error(), "add-public-keys patch is missing publicKeys")
	})
	t.Run("success from new", func(t *testing.T) {
		p, err := NewAddPublicKeysPatch(testAddPublicKeys)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), AddPublicKeys)
		require.Equal(t, p.GetStringValue(PublicKeys), testAddPublicKeys)
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
		require.Contains(t, err.Error(), "remove-public-keys patch is missing publicKeys")
	})
	t.Run("success from new", func(t *testing.T) {
		const ids = `["key1", "key2"]`
		p, err := NewRemovePublicKeysPatch(ids)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), RemovePublicKeys)
		require.Equal(t, p.GetStringValue(PublicKeys), ids)
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
		"authentication": [{
			"id": "#keys-1",
			"type": "RsaVerificationKey2018",
			"publicKeyPem": "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n"
  		}],
		"service": [{
			"id":"#vcs",
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
	"publicKeys": [{
		"id": "key1",
		"usage": ["ops"],
		"type": "Secp256k1VerificationKey2018",
		"publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
	}]
}`

const testAddPublicKeys = `[
	{
      "id": "key1",
      "usage": ["ops"],
      "type": "Secp256k1VerificationKey2018",
      "publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
    }
  ]`

const removePublicKeysPatch = `{
  "action": "remove-public-keys",
  "publicKeys": ["key1", "key2"]
}`

const testDoc = `{
  "authentication": [{
    "id": "#keys-1",
    "type": "RsaVerificationKey2018",
    "publicKeyPem": "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n"
  }],
  "service": [{
    "id":"#vcs",
    "type": "VerifiableCredentialService",
    "serviceEndpoint": "https://example.com/vc/"
  }]
}`
