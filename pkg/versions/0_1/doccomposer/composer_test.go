/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doccomposer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

const invalid = "invalid"

func TestApplyPatches(t *testing.T) {
	documentComposer := New()

	t.Run("success - add one key to existing doc with two keys", func(t *testing.T) {
		original, err := setupDefaultDoc()
		require.NoError(t, err)
		require.Equal(t, 2, len(original.PublicKeys()))

		addPublicKeys, err := patch.NewAddPublicKeysPatch(addKeys)
		require.NoError(t, err)

		doc, err := documentComposer.ApplyPatches(original, []patch.Patch{addPublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		didDoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 3, len(didDoc.PublicKeys()))
		require.Equal(t, "key1", didDoc.PublicKeys()[0].ID())
		require.Equal(t, "key2", didDoc.PublicKeys()[1].ID())
		require.Equal(t, "key3", didDoc.PublicKeys()[2].ID())

		// make sure that original document is not modified
		require.Equal(t, 2, len(original.PublicKeys()))
	})

	t.Run("action not supported", func(t *testing.T) {
		p, err := patch.NewAddServiceEndpointsPatch("{}")
		require.NoError(t, err)

		p["action"] = invalid

		doc, err := documentComposer.ApplyPatches(make(document.Document), []patch.Patch{p})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "not supported")
	})
	t.Run("error - original document deep copy fails (not json)", func(t *testing.T) {
		doc := make(document.Document)
		doc["key"] = make(chan int)

		doc, err := documentComposer.ApplyPatches(doc, nil)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "json: unsupported type: chan int")
	})
}

func TestApplyPatches_PatchesFromOpaqueDoc(t *testing.T) {
	documentComposer := New()

	t.Run("success", func(t *testing.T) {
		patches, err := patch.PatchesFromDocument(testDoc)
		require.NoError(t, err)

		doc, err := documentComposer.ApplyPatches(make(document.Document), patches)
		require.NoError(t, err)
		require.NotNil(t, doc)

		didDoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())
		require.Len(t, didDoc.Services(), 2)
		require.Len(t, didDoc.PublicKeys(), 2)
	})
}

func TestApplyPatches_ReplacePatch(t *testing.T) {
	documentComposer := New()

	t.Run("success", func(t *testing.T) {
		replace, err := patch.NewReplacePatch(replaceDoc)
		require.NoError(t, err)

		doc, err := documentComposer.ApplyPatches(make(document.Document), []patch.Patch{replace})
		require.NoError(t, err)
		require.NotNil(t, doc)

		didDoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())
		require.Len(t, didDoc.Services(), 1)
		require.Len(t, didDoc.PublicKeys(), 1)
	})
}

func TestApplyPatches_JSON(t *testing.T) {
	documentComposer := New()

	t.Run("success", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		ietf, err := patch.NewJSONPatch(patches)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{ietf})
		require.NoError(t, err)
		require.NotNil(t, doc)
	})
	t.Run("invalid operation", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		ietf, err := patch.NewJSONPatch(invalidPatches)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{ietf})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "Unexpected kind: invalid")
	})
}

func TestApplyPatches_AddPublicKeys(t *testing.T) {
	documentComposer := New()

	t.Run("succes - add one key to existing two keys", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addPublicKeys, err := patch.NewAddPublicKeysPatch(addKeys)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{addPublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 3, len(diddoc.PublicKeys()))
		require.Equal(t, "key1", diddoc.PublicKeys()[0].ID())
		require.Equal(t, "key2", diddoc.PublicKeys()[1].ID())
		require.Equal(t, "key3", diddoc.PublicKeys()[2].ID())
	})
	t.Run("success - add existing public key to document; old one will be replaced", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addPublicKeys, err := patch.NewAddPublicKeysPatch(updateExistingKey)
		require.NoError(t, err)

		// existing public key will be replaced with new one that has type 'updatedKeyType'
		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{addPublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		keys := diddoc.PublicKeys()
		require.Equal(t, 2, len(keys))
		require.Equal(t, 1, len(keys[1].Purpose()))
	})
	t.Run("add same key twice - no error; one key added", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addPublicKeys, err := patch.NewAddPublicKeysPatch(addKeys)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{addPublicKeys, addPublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 3, len(diddoc.PublicKeys()))
	})
}

func TestApplyPatches_RemovePublicKeys(t *testing.T) {
	documentComposer := New()

	t.Run("success - remove existing key", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		removePublicKeys, err := patch.NewRemovePublicKeysPatch(`["key1"]`)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{removePublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		didDoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 1, len(didDoc.PublicKeys()))
	})

	t.Run("success - remove existing and non-existing keys", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		removePublicKeys, err := patch.NewRemovePublicKeysPatch(`["key1", "key3"]`)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{removePublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 1, len(diddoc.PublicKeys()))
	})
	t.Run("success - add and remove same key; doc stays at two keys", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addPublicKeys, err := patch.NewAddPublicKeysPatch(addKeys)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{addPublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		removePublicKeys, err := patch.NewRemovePublicKeysPatch(`["key3"]`)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{removePublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 2, len(diddoc.PublicKeys()))
	})
}

func TestApplyPatches_AddServiceEndpoints(t *testing.T) {
	documentComposer := New()

	t.Run("success - add new service to existing two services", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addServices, err := patch.NewAddServiceEndpointsPatch(addServices)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{addServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 3, len(diddoc.Services()))
		require.Equal(t, "svc1", diddoc.Services()[0].ID())
		require.Equal(t, "svc2", diddoc.Services()[1].ID())
		require.Equal(t, "svc3", diddoc.Services()[2].ID())
	})
	t.Run("success - add existing service to document ", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addServices, err := patch.NewAddServiceEndpointsPatch(updateExistingService)
		require.NoError(t, err)

		// existing service will be replaced with new one that has type 'updatedService'
		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{addServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		services := diddoc.Services()
		require.Equal(t, 2, len(services))
		require.Equal(t, diddoc.Services()[1].Type(), "updatedServiceType")
	})
	t.Run("add same service twice - no error; one service added", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addServices, err := patch.NewAddServiceEndpointsPatch(addServices)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{addServices, addServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 3, len(diddoc.Services()))
	})
}

func TestApplyPatches_RemoveServiceEndpoints(t *testing.T) {
	documentComposer := New()

	t.Run("success - remove existing service", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		removeServices, err := patch.NewRemoveServiceEndpointsPatch(`["svc1"]`)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{removeServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 1, len(diddoc.Services()))
	})

	t.Run("success - remove existing and non-existing service", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		removeServices, err := patch.NewRemoveServiceEndpointsPatch(`["svc1", "svc3"]`)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{removeServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 1, len(diddoc.Services()))
	})
	t.Run("success - add and remove same service; doc stays at two services", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addServices, err := patch.NewAddServiceEndpointsPatch(addServices)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{addServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		removeServices, err := patch.NewRemoveServiceEndpointsPatch(`["svc3"]`)
		require.NoError(t, err)

		doc, err = documentComposer.ApplyPatches(doc, []patch.Patch{removeServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 2, len(diddoc.Services()))
	})
}

func setupDefaultDoc() (document.Document, error) {
	documentComposer := New()

	patches, err := patch.PatchesFromDocument(testDoc)
	if err != nil {
		return nil, err
	}

	return documentComposer.ApplyPatches(make(document.Document), patches)
}

const invalidPatches = `[
	{
      "op": "invalid",
      "path": "/test",
      "value": "new value"
	}
]`

const patches = `[
	{
      "op": "replace",
      "path": "/test",
      "value": "new value"
	}
]`

const testDoc = `{
	"publicKey": [
		{
		  "id": "key1",
		  "type": "JsonWebKey2020",
		  "purposes": ["assertionMethod"],
		  "publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
		},
		{
		  "id": "key2",
		  "type": "JsonWebKey2020",
		  "purposes": ["authentication"],
		  "publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
		}
	],
  	"service": [
    {
      "id": "svc1",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://hub.my-personal-server.com"
    },
    {
      "id": "svc2",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://some-cloud.com/hub"
    }
  ]
}`

const addKeys = `[{
		  "id": "key3",
		  "type": "JsonWebKey2020",
		  "publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
		}]`

const updateExistingKey = `[{
	"id": "key2",
	"type": "JsonWebKey2020",
	"purposes": ["assertionMethod"],
	"publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}]`

const addServices = `[
    {
      "id": "svc3",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://hub.my-personal-server.com"
    }
  ]`

const updateExistingService = `[
    {
      "id": "svc2",
      "type": "updatedServiceType",
      "serviceEndpoint": "http://hub.my-personal-server.com"
    }
  ]`

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
