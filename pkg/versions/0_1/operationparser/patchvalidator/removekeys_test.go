package patchvalidator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

func TestRemovePublicKeysPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(removePublicKeysPatch))
		require.NoError(t, err)

		err = NewRemovePublicKeysValidator().Validate(p)
		require.NoError(t, err)
	})
	t.Run("error - missing public key ids", func(t *testing.T) {
		p := make(patch.Patch)
		p[patch.ActionKey] = patch.RemovePublicKeys

		err := NewRemovePublicKeysValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "remove-public-keys patch is missing key: ids")
	})
	t.Run("error - invalid add public keys value", func(t *testing.T) {
		p := make(patch.Patch)
		p[patch.ActionKey] = patch.RemovePublicKeys
		p[patch.IdsKey] = "whatever"

		err := NewRemovePublicKeysValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected array of interfaces")
	})
	t.Run("invalid public key ids", func(t *testing.T) {
		const ids = `["a123*b456"]`
		p, err := patch.NewRemovePublicKeysPatch(ids)
		require.NoError(t, err)

		err = NewRemovePublicKeysValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id contains invalid characters")
	})
}

const removePublicKeysPatch = `{
  "action": "remove-public-keys",
  "ids": ["key1", "key2"]
}`
