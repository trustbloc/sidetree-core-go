/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

const invalid = "invalid"

func TestApplyPatches(t *testing.T) {
	t.Run("action not supported", func(t *testing.T) {
		replace, err := patch.NewReplacePatch("{}")
		require.NoError(t, err)

		replace["action"] = invalid

		doc, err := ApplyPatches(nil, []patch.Patch{replace})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "not supported")
	})
}

func TestApplyPatches_Replace(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		replace, err := patch.NewReplacePatch(testDoc)
		require.NoError(t, err)

		doc, err := ApplyPatches(nil, []patch.Patch{replace})
		require.NoError(t, err)
		require.NotNil(t, doc)
	})
}

func TestApplyPatches_JSON(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		ietf, err := patch.NewJSONPatch(patches)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{ietf})
		require.NoError(t, err)
		require.NotNil(t, doc)
	})
	t.Run("invalid json", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		ietf, err := patch.NewJSONPatch(patches)
		require.NoError(t, err)

		ietf["patches"] = invalid

		doc, err = ApplyPatches(doc, []patch.Patch{ietf})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "invalid character")
	})
	t.Run("invalid operation", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		ietf, err := patch.NewJSONPatch(invalidPatches)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{ietf})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "Unexpected kind: invalid")
	})
}

func TestApplyPatches_AddPublicKeys(t *testing.T) {
	t.Run("succes - add one key to existing two keys", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addPublicKeys, err := patch.NewAddPublicKeysPatch(addKeys)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{addPublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 3, len(diddoc.PublicKeys()))
	})
	t.Run("add same key twice - no error; one key added", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addPublicKeys, err := patch.NewAddPublicKeysPatch(addKeys)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{addPublicKeys, addPublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 3, len(diddoc.PublicKeys()))
	})
	t.Run("invalid json", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addPublicKeys, err := patch.NewAddPublicKeysPatch(addKeys)
		require.NoError(t, err)
		addPublicKeys["publicKeys"] = invalid

		doc, err = ApplyPatches(doc, []patch.Patch{addPublicKeys})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "invalid character")
	})
}

func TestApplyPatches_RemovePublicKeys(t *testing.T) {
	t.Run("success - remove existing key", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		removePublicKeys, err := patch.NewRemovePublicKeysPatch(`["key1"]`)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{removePublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 1, len(diddoc.PublicKeys()))
	})

	t.Run("success - remove existing and non-existing keys", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		removePublicKeys, err := patch.NewRemovePublicKeysPatch(`["key1", "key3"]`)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{removePublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 1, len(diddoc.PublicKeys()))
	})
	t.Run("invalid json", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addPublicKeys, err := patch.NewRemovePublicKeysPatch(removeKeys)
		require.NoError(t, err)
		addPublicKeys["publicKeys"] = invalid

		doc, err = ApplyPatches(doc, []patch.Patch{addPublicKeys})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "invalid character")
	})
}

func setupDefaultDoc() (document.Document, error) {
	replace, err := patch.NewReplacePatch(testDoc)
	if err != nil {
		return nil, err
	}

	return ApplyPatches(nil, []patch.Patch{replace})
}

const invalidPatches = `[
	{
      "op": "invalid",
      "path": "/service",
      "value": "new value"
	}
]`

const patches = `[
	{
      "op": "replace",
      "path": "/service",
      "value": "new value"
	}
]`

const testDoc = `{
	"publicKey": [{
		"id": "key1",
		"usage": ["ops"],
		"type": "Secp256k1VerificationKey2018",
		"publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
	},
	{
		"id": "key2",
		"usage": ["ops"],
		"type": "Secp256k1VerificationKey2018",
		"publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
	}],
  	"service": [{
    	"id":"#vcs",
    	"type": "VerifiableCredentialService",
    	"serviceEndpoint": "https://example.com/vc/"
  }]
}`

const addKeys = `[{
		"id": "key3",
		"usage": ["ops"],
		"type": "Secp256k1VerificationKey2018",
		"publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
	}]`

const removeKeys = `["key1", "key2"]`
