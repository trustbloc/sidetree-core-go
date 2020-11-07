package patchvalidator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

func TestAddPublicKeysPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addPublicKeysPatch))
		require.NoError(t, err)

		err = NewAddPublicKeysValidator().Validate(p)
		require.NoError(t, err)
	})
	t.Run("error - missing value", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addPublicKeysPatch))
		require.NoError(t, err)

		delete(p, patch.PublicKeys)
		err = NewAddPublicKeysValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "add-public-keys patch is missing key: publicKeys")
	})
	t.Run("error - invalid value for public keys", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addPublicKeysPatch))
		require.NoError(t, err)

		p[patch.PublicKeys] = ""
		err = NewAddPublicKeysValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid add public keys value: expected array of interfaces")
	})
}

const addPublicKeysPatch = `{
   "action": "add-public-keys",
   "publicKeys": [{
      "id": "key1",
      "type": "JsonWebKey2020",
      "purposes": ["assertionMethod"],
      "publicKeyJwk": {
         "kty": "EC",
         "crv": "P-256K",
         "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
         "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
   }]
}`
