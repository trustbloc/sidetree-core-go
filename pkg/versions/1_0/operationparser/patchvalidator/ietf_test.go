package patchvalidator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

func TestIETFPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(ietfPatch))
		require.NoError(t, err)

		err = NewJSONValidator().Validate(p)
		require.NoError(t, err)
	})
	t.Run("error - path not found", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(ietfPatchNoPath))
		require.NoError(t, err)

		err = NewJSONValidator().Validate(p)
		require.Error(t, err)
		require.Equal(t, err.Error(), "ietf-json-patch: path not found")
	})
	t.Run("error - cannot update services", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(ietfServicesPatch))
		require.NoError(t, err)

		err = NewJSONValidator().Validate(p)
		require.Error(t, err)
		require.Equal(t, err.Error(), "ietf-json-patch: cannot modify services")
	})
	t.Run("error - cannot update public keys", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(ietfPublicKeysPatch))
		require.NoError(t, err)

		err = NewJSONValidator().Validate(p)
		require.Error(t, err)
		require.Equal(t, err.Error(), "ietf-json-patch: cannot modify public keys")
	})
	t.Run("error missing patches", func(t *testing.T) {
		p := make(patch.Patch)
		p[patch.ActionKey] = patch.JSONPatch

		err := NewJSONValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ietf-json-patch patch is missing key: patches")
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

const ietfPatchNoPath = `{
  "action": "ietf-json-patch",
  "patches": [{
      "op": "replace",
      "value": "value"
   }]
}`

const ietfServicesPatch = `{
  "action": "ietf-json-patch",
  "patches": [{
      "op": "replace",
      "path": "/service",
      "value": "new value"
   }]
}`

const ietfPublicKeysPatch = `{
  "action": "ietf-json-patch",
  "patches": [{
      "op": "replace",
      "path": "/publicKey/0/type",
      "value": "new type"
   }]
}`
