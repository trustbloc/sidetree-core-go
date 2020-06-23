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
		p, err := patch.NewAddServiceEndpointsPatch("{}")
		require.NoError(t, err)

		p["action"] = invalid

		doc, err := ApplyPatches(make(document.Document), []patch.Patch{p})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "not supported")
	})
}

func TestApplyPatches_PatchesFromOpaqueDoc(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patches, err := patch.PatchesFromDocument(testDoc)
		require.NoError(t, err)

		doc, err := ApplyPatches(make(document.Document), patches)
		require.NoError(t, err)
		require.NotNil(t, doc)

		didDoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())
		require.Len(t, didDoc.Services(), 2)
		require.Len(t, didDoc.PublicKeys(), 2)
	})
}

func TestApplyPatches_ReplacePatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		replace, err := patch.NewReplacePatch(replaceDoc)
		require.NoError(t, err)

		doc, err := ApplyPatches(make(document.Document), []patch.Patch{replace})
		require.NoError(t, err)
		require.NotNil(t, doc)

		didDoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())
		require.Len(t, didDoc.Services(), 1)
		require.Len(t, didDoc.PublicKeys(), 1)
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
		require.Contains(t, err.Error(), "expected array")
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
	t.Run("success - add existing public key to document; old one will be replaced", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addPublicKeys, err := patch.NewAddPublicKeysPatch(updateExistingKey)
		require.NoError(t, err)

		// existing public key will be replaced with new one that has type 'updatedKeyType'
		doc, err = ApplyPatches(doc, []patch.Patch{addPublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		keys := diddoc.PublicKeys()
		require.Equal(t, 2, len(keys))
		for _, key := range keys {
			if key.ID() == "key2" {
				require.Equal(t, 1, len(key.Purpose()))
			}
		}
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
		addPublicKeys["public_keys"] = invalid

		doc, err = ApplyPatches(doc, []patch.Patch{addPublicKeys})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "expected array of interfaces")
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

		didDoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 1, len(didDoc.PublicKeys()))
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

		removePublicKeys, err := patch.NewRemovePublicKeysPatch(removeKeys)
		require.NoError(t, err)
		removePublicKeys["public_keys"] = invalid

		doc, err = ApplyPatches(doc, []patch.Patch{removePublicKeys})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "expected array")
	})
	t.Run("invalid public key ids", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		removePublicKeys, err := patch.NewRemovePublicKeysPatch(removeKeys)
		require.NoError(t, err)
		removePublicKeys["public_keys"] = []interface{}{"a&b"}

		doc, err = ApplyPatches(doc, []patch.Patch{removePublicKeys})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "id contains invalid characters")
	})
	t.Run("success - add and remove same key; doc stays at two keys", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addPublicKeys, err := patch.NewAddPublicKeysPatch(addKeys)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{addPublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		removePublicKeys, err := patch.NewRemovePublicKeysPatch(`["key3"]`)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{removePublicKeys})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 2, len(diddoc.PublicKeys()))
	})
}

func TestApplyPatches_AddServiceEndpoints(t *testing.T) {
	t.Run("success - add new service to existing two services", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addServices, err := patch.NewAddServiceEndpointsPatch(addServices)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{addServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 3, len(diddoc.Services()))
	})
	t.Run("success - add existing service to document ", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addServices, err := patch.NewAddServiceEndpointsPatch(updateExistingService)
		require.NoError(t, err)

		// existing service will be replaced with new one that has type 'updatedService'
		doc, err = ApplyPatches(doc, []patch.Patch{addServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		services := diddoc.Services()
		require.Equal(t, 2, len(services))
		for _, svc := range services {
			if svc.ID() == "svc2" {
				require.Equal(t, svc.Type(), "updatedServiceType")
			}
		}
	})
	t.Run("add same service twice - no error; one service added", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addServices, err := patch.NewAddServiceEndpointsPatch(addServices)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{addServices, addServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 3, len(diddoc.Services()))
	})
	t.Run("invalid json", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addServices, err := patch.NewAddServiceEndpointsPatch(addServices)
		require.NoError(t, err)
		addServices["service_endpoints"] = invalid

		doc, err = ApplyPatches(doc, []patch.Patch{addServices})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "expected array")
	})
}

func TestApplyPatches_RemoveServiceEndpoints(t *testing.T) {
	t.Run("success - remove existing service", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		removeServices, err := patch.NewRemoveServiceEndpointsPatch(`["svc1"]`)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{removeServices})
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

		doc, err = ApplyPatches(doc, []patch.Patch{removeServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 1, len(diddoc.Services()))
	})
	t.Run("invalid json", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		removeServices, err := patch.NewRemoveServiceEndpointsPatch(removeServices)
		require.NoError(t, err)
		removeServices["ids"] = invalid

		doc, err = ApplyPatches(doc, []patch.Patch{removeServices})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "expected array")
	})
	t.Run("invalid service ids", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		removeServices, err := patch.NewRemoveServiceEndpointsPatch(removeServices)
		require.NoError(t, err)
		removeServices["ids"] = []interface{}{"svc", "a&b"}

		doc, err = ApplyPatches(doc, []patch.Patch{removeServices})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "id contains invalid characters")
	})
	t.Run("success - add and remove same service; doc stays at two services", func(t *testing.T) {
		doc, err := setupDefaultDoc()
		require.NoError(t, err)

		addServices, err := patch.NewAddServiceEndpointsPatch(addServices)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{addServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		removeServices, err := patch.NewRemoveServiceEndpointsPatch(`["svc3"]`)
		require.NoError(t, err)

		doc, err = ApplyPatches(doc, []patch.Patch{removeServices})
		require.NoError(t, err)
		require.NotNil(t, doc)

		diddoc := document.DidDocumentFromJSONLDObject(doc)
		require.Equal(t, 2, len(diddoc.Services()))
	})
}

func setupDefaultDoc() (document.Document, error) {
	patches, err := patch.PatchesFromDocument(testDoc)
	if err != nil {
		return nil, err
	}

	return ApplyPatches(make(document.Document), patches)
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
		  "id": "key2",
		  "type": "JwsVerificationKey2020",
		  "purpose": ["ops", "general"],
		  "jwk": {
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
      "endpoint": "http://hub.my-personal-server.com"
    },
    {
      "id": "svc2",
      "type": "SecureDataStore",
      "endpoint": "http://some-cloud.com/hub"
    }
  ]
}`

const addKeys = `[{
		  "id": "key3",
		  "type": "JwsVerificationKey2020",
		  "purpose": ["ops", "general"],
		  "jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
		}]`

const updateExistingKey = `[{
	"id": "key2",
	"type": "JwsVerificationKey2020",
	"purpose": ["ops"],
	"jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}]`

const removeKeys = `["key1", "key2"]`

const addServices = `[
    {
      "id": "svc3",
      "type": "SecureDataStore",
      "endpoint": "http://hub.my-personal-server.com"
    }
  ]`

const updateExistingService = `[
    {
      "id": "svc2",
      "type": "updatedServiceType",
      "endpoint": "http://hub.my-personal-server.com"
    }
  ]`

const removeServices = `["svc1", "svc2"]`

const replaceDoc = `{
	"public_keys": [
	{
		"id": "key-1",
		"purpose": ["auth"],
		"type": "EcdsaSecp256k1VerificationKey2019",
		"jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}],
	"service_endpoints": [
	{
		"id": "sds3",
		"type": "SecureDataStore",
		"endpoint": "http://hub.my-personal-server.com"
	}]
}`
