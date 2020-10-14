/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patchvalidator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

func TestValidateReplacePatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(replacePatch))
		require.NoError(t, err)

		err = NewReplaceValidator().Validate(p)
		require.NoError(t, err)
	})
	t.Run("missing document", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(replacePatch))
		require.NoError(t, err)
		require.NotNil(t, p)

		delete(p, patch.DocumentKey)
		err = NewReplaceValidator().Validate(p)
		require.Contains(t, err.Error(), "replace patch is missing key: document")
	})
	t.Run("error - document has invalid property", func(t *testing.T) {
		doc, err := document.FromBytes([]byte(replaceDocWithExtraProperties))
		require.NoError(t, err)

		p := make(patch.Patch)
		p[patch.ActionKey] = patch.Replace
		p[patch.DocumentKey] = doc.JSONLdObject()

		err = NewReplaceValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key 'id' is not allowed in replace document")
	})
	t.Run("error - public keys (missing type)", func(t *testing.T) {
		p, err := patch.NewReplacePatch(replaceDocInvalidPublicKey)
		require.NoError(t, err)
		require.NotNil(t, p)

		err = NewReplaceValidator().Validate(p)
		require.Contains(t, err.Error(), "invalid number of public key properties")
	})
	t.Run("error - services (missing endpoint)", func(t *testing.T) {
		p, err := patch.NewReplacePatch(replaceDocInvalidServiceEndpoint)
		require.NoError(t, err)
		require.NotNil(t, p)

		err = NewReplaceValidator().Validate(p)
		require.Contains(t, err.Error(), "service endpoint is missing")
	})
}

const replacePatch = `{
   "action": "replace",
   "document": {
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
   }
}`

const replaceDocWithExtraProperties = `{
   "id": "some-id",
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
   }]
}`

const replaceDocInvalidPublicKey = `{
   "public_keys": [
   {
      "id": "key-1",
      "purpose": ["auth"],
      "jwk": {
         "kty": "EC",
         "crv": "P-256K",
         "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
         "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
   }]
}`

const replaceDocInvalidServiceEndpoint = `{
   "service_endpoints": [
   {
      "id": "sds3",
      "type": "SecureDataStore"
   }]
}`
