package patchvalidator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

func TestRemoveServiceEndpointsPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(removeServiceEndpoints))
		require.NoError(t, err)

		err = NewRemoveServicesValidator().Validate(p)
		require.NoError(t, err)
	})
	t.Run("error - missing public key ids", func(t *testing.T) {
		p := make(patch.Patch)
		p[patch.ActionKey] = patch.RemoveServiceEndpoints

		err := NewRemoveServicesValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "remove-services patch is missing key: ids")
	})
	t.Run("error - invalid service ids", func(t *testing.T) {
		p := make(patch.Patch)
		p[patch.ActionKey] = patch.RemoveServiceEndpoints
		p[patch.IdsKey] = "invalid"

		err := NewRemoveServicesValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected array of interfaces")
	})
	t.Run("invalid service ids", func(t *testing.T) {
		const ids = `["a123*b456"]`
		p, err := patch.NewRemoveServiceEndpointsPatch(ids)
		require.NoError(t, err)

		err = NewRemoveServicesValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id contains invalid characters")
	})
}

const removeServiceEndpoints = `{
  "action": "remove-services",
  "ids": ["sds1", "sds2"]
}`
