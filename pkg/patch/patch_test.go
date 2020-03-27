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
		patch, err := FromBytes([]byte(invalidReplacePatch))
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
		patch, err := FromBytes([]byte(invalidReplacePatch))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "replace patch is missing document")
	})
	t.Run("success from new", func(t *testing.T) {
		p := NewReplacePatch(testDoc)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), Replace)
	})
}

func TestIETFPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patch, err := FromBytes([]byte(ietfPatch))
		require.NoError(t, err)
		require.NotNil(t, patch)
		require.Equal(t, patch.GetAction(), JSONPatch)
	})
	t.Run("invalid replace patch", func(t *testing.T) {
		patch, err := FromBytes([]byte(invalidIETFPatch))
		require.Error(t, err)
		require.Nil(t, patch)
		require.Contains(t, err.Error(), "ietf-json-patch patch is missing patches")
	})
	t.Run("success from new", func(t *testing.T) {
		p := NewJSONPatch(patches)
		require.NotNil(t, p)
		require.Equal(t, p.GetAction(), JSONPatch)
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

const invalidReplacePatch = `{
	"action": "replace"
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

const invalidIETFPatch = `{
	"action": "ietf-json-patch"
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
